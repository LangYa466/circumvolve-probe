package org.gfwreport.probe;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Reproduces the two-stage evaluator of the CircumVolve paper for DNS and TLS.
 * Stage 1 asks whether a real resolver or server still accepts the crafted
 * message; stage 2 asks whether a simulated DPI matcher still finds the blocked
 * name. Every outcome is an enum so the UI owns all wording.
 */
public final class Probes {

    private Probes() {}

    /** The name the censor's blocklist holds, and the one we try to hide. */
    public static final String BLOCKED = "pornhub.com";

    /**
     * Hostname the GFW blocks by SNI. It sits behind Cloudflare, so the same
     * address answers for allowed names — that is what makes the control case
     * below meaningful.
     */
    public static final String TLS_HOST = "signal.org";

    /** Address to fall back to when DNS is unusable. */
    public static final String TLS_IP_FALLBACK = "104.18.11.47";

    /** Allowed hostname on the same address; the control group for SNI blocking. */
    public static final String TLS_CONTROL_HOST = "www.cloudflare.com";

    /** Resolvers tried in order when picking a server address. */
    private static final String[] RESOLVERS = {"1.1.1.1", "8.8.8.8", "9.9.9.9"};

    /** Long enough for the real resolver to answer after any injector races it. */
    private static final int DNS_WINDOW_MS = 1200;

    /**
     * Injectors fire probabilistically: the same datagram can draw two forged
     * replies on one run and none on the next. Each case is sent this many
     * times so the report shows a rate instead of a single sample.
     */
    private static final int DNS_REPEATS = 3;

    /** Per-read timeout inside the polling window. */
    private static final int DNS_POLL_SLICE_MS = 120;

    /** Matcher depth for the "smarter" simulated DPI. */
    private static final int POINTER_DEPTH = 8;

    private static final int QTYPE_A = 0x0001;
    private static final int QCLASS_IN = 0x0001;
    private static final byte[] QTAIL = {0x00, 0x01, 0x00, 0x01};
    private static final int DNS_HEADER_LEN = 12;

    /** Reports how far a run has got; called from the probe thread. */
    public interface Progress {
        void onStep(int done, int total, int labelRes);
    }

    /** Number of DNS cases in {@link #runDns}. */
    private static final int DNS_CASES = 7;

    /** Number of TLS cases in {@link #runTls}, including the control probe. */
    private static final int TLS_CASES = 9;

    /** How a simulated DPI matcher treats the crafted datagram. */
    public enum Dpi {
        BOTH_BYPASS,
        LITERAL_DETECTED,
        PARTIAL_POINTER,
        FIRST_DETECTED,
        FIRST_BYPASS,
        BYPASS;

        public boolean bypassed() { return this != LITERAL_DETECTED && this != FIRST_DETECTED; }
    }

    /**
     * Whether the run actually demonstrated an SNI bypass. A bypass needs a
     * control group: the untouched ClientHello must be refused while some
     * variant gets through. If the baseline handshakes, the host is not blocked
     * on this path and no conclusion can be drawn.
     */
    public enum SniVerdict {
        /** Baseline and control both handshake: this host is not SNI-blocked here. */
        NOT_BLOCKED,
        /** No address accepted the control name, so nothing below the name was reachable. */
        NO_VERIFIED_ADDRESS,
        /** Even the control name is refused: the address itself is blocked, no conclusion. */
        IP_BLOCKED,
        /** Baseline refused, no variant got through. */
        BLOCKED_NO_EVASION,
        /** Baseline refused, control fine, some variant handshook. */
        BYPASS_PROVEN
    }

    /** What the real TLS server answered. */
    public enum Server {
        NOT_PROBED, SERVER_HELLO, ALERT, NOT_TLS, TIMEOUT, TRUNCATED,
        /** Connection was reset or closed with no TLS reply: injection or address block. */
        RESET,
        /** TCP never established. */
        CONNECT_FAILED,
        ERROR;

        static Server parse(String raw) {
            if (raw == null) return NOT_PROBED;
            switch (raw) {
                case "ServerHello": return SERVER_HELLO;
                case "Alert": return ALERT;
                case "not-tls": return NOT_TLS;
                case "timeout": return TIMEOUT;
                case "truncated": return TRUNCATED;
                // EOF right after our ClientHello and before any record is the
                // same observable as a forged RST.
                case "no-reply": return RESET;
                default: return ERROR;
            }
        }

        public boolean handshakeOk() { return this == SERVER_HELLO; }
    }

    /** One reply seen for a query. */
    public static final class Reply {
        public final int elapsedMs;
        public final String ips;
        public final String error;

        private Reply(int elapsedMs, String ips, String error) {
            this.elapsedMs = elapsedMs;
            this.ips = ips;
            this.error = error;
        }

        static Reply answer(int elapsedMs, String ips) { return new Reply(elapsedMs, ips, null); }
        static Reply failure(String error) { return new Reply(-1, null, error); }

        /** Every address in this reply belongs to the 198.18.0.0/15 fake-ip range. */
        public boolean fakeIp() {
            if (ips == null || ips.isEmpty()) return false;
            for (String ip : ips.split(",")) {
                if (!ip.startsWith("198.18.") && !ip.startsWith("198.19.")) return false;
            }
            return true;
        }
    }

    /** One probe case and everything measured about it. */
    public static final class Result {
        /** String resource id of the case name. */
        public final int nameRes;
        /** String resource id of the case description. */
        public final int noteRes;
        public Dpi dpi;
        public Server server = Server.NOT_PROBED;
        /** Every reply across all runs, in arrival order per run. */
        public final List<Reply> replies = new ArrayList<>();
        /** How many times this case was sent. */
        public int runs;
        /** Of those runs, how many drew more than one reply. */
        public int injectedRuns;
        /** True for the allowed-name probe that proves the block is SNI-only. */
        public boolean control;

        Result(int nameRes, int noteRes) {
            this.nameRes = nameRes;
            this.noteRes = noteRes;
        }

        public boolean bypassed() { return dpi != null && dpi.bypassed(); }
        /** True when at least one run drew more than one reply. */
        public boolean injected() { return injectedRuns > 0; }
        /** True when every run drew more than one reply. */
        public boolean injectedEveryRun() { return runs > 0 && injectedRuns == runs; }
        public boolean answered() { return !replies.isEmpty(); }

        /** True when every reply came from a fake-ip range, i.e. a local proxy. */
        public boolean proxied() {
            if (replies.isEmpty()) return false;
            for (Reply r : replies) if (!r.fakeIp()) return false;
            return true;
        }
    }

    // ---------------- DNS ----------------

    private static byte[] header(int id, int flags, int qd, int an, int ns, int ar) {
        return new byte[] {
                (byte) (id >> 8), (byte) id,
                (byte) (flags >> 8), (byte) flags,
                (byte) (qd >> 8), (byte) qd,
                (byte) (an >> 8), (byte) an,
                (byte) (ns >> 8), (byte) ns,
                (byte) (ar >> 8), (byte) ar,
        };
    }

    private static byte[] qname(String name) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (String label : name.split("\\.")) {
            byte[] b = label.getBytes(StandardCharsets.US_ASCII);
            out.write(b.length);
            out.write(b, 0, b.length);
        }
        out.write(0);
        return out.toByteArray();
    }

    static byte[] dnsSeed() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(header(0x1234, 0x0100, 1, 0, 0, 0));
        out.writeBytes(qname(BLOCKED));
        out.writeBytes(QTAIL);
        return out.toByteArray();
    }

    /** QNAME at offset 12 replaced with a pointer to a copy placed later in the packet. */
    static byte[] dnsForwardPointer() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(header(0x1234, 0x0100, 1, 0, 0, 0));
        out.write(0xC0);
        out.write(32);
        out.writeBytes(QTAIL);
        while (out.size() < 32) out.write(0);
        out.writeBytes(qname(BLOCKED));
        return out.toByteArray();
    }

    /** Two chained forward pointers, then the literal name. */
    static byte[] dnsPointerChain() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(header(0x1234, 0x0100, 1, 0, 0, 0));
        out.write(0xC0);
        out.write(DNS_HEADER_LEN + 2);
        out.write(0xC0);
        out.write(DNS_HEADER_LEN + 4);
        out.writeBytes(qname(BLOCKED));
        out.writeBytes(QTAIL);
        return out.toByteArray();
    }

    /** Second question carries the blocked name, first carries a decoy. */
    static byte[] dnsDecoySecondQuestion() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(header(0x1234, 0x0100, 2, 0, 0, 0));
        out.writeBytes(qname("example.com"));
        out.writeBytes(QTAIL);
        out.writeBytes(qname(BLOCKED));
        out.writeBytes(QTAIL);
        return out.toByteArray();
    }

    /** QDCOUNT claims two questions, only one is present. */
    static byte[] dnsFakeQdcount() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(header(0x1234, 0x0100, 2, 0, 0, 0));
        out.writeBytes(qname(BLOCKED));
        out.writeBytes(QTAIL);
        return out.toByteArray();
    }

    /** Reserved Z bit and TC bit set. */
    static byte[] dnsFlagsZtc() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(header(0x1234, 0x0100 | 0x0200 | 0x0040, 1, 0, 0, 0));
        out.writeBytes(qname(BLOCKED));
        out.writeBytes(QTAIL);
        return out.toByteArray();
    }

    /** ANCOUNT/ARCOUNT claim records that are not present. */
    static byte[] dnsFakeCounts() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(header(0x1234, 0x0100, 1, 3, 0, 2));
        out.writeBytes(qname(BLOCKED));
        out.writeBytes(QTAIL);
        return out.toByteArray();
    }

    /** Naive matcher: literal QNAME at offset 12, no pointer following. */
    static boolean dpiNaiveLiteral(byte[] msg) {
        if (msg.length <= DNS_HEADER_LEN) return false;
        StringBuilder name = new StringBuilder();
        int i = DNS_HEADER_LEN;
        while (i < msg.length) {
            int len = msg[i] & 0xFF;
            if (len == 0) break;
            if (len >= 0xC0) return false;
            if (i + 1 + len > msg.length) return false;
            if (name.length() > 0) name.append('.');
            name.append(new String(msg, i + 1, len, StandardCharsets.US_ASCII));
            i += 1 + len;
        }
        return name.toString().toLowerCase(Locale.ROOT).contains(BLOCKED);
    }

    /** Slightly smarter matcher: follows compression pointers up to a fixed depth. */
    static boolean dpiDepthLimited(byte[] msg) {
        return walkName(msg, DNS_HEADER_LEN, POINTER_DEPTH).toLowerCase(Locale.ROOT).contains(BLOCKED);
    }

    private static String walkName(byte[] msg, int start, int maxHops) {
        StringBuilder name = new StringBuilder();
        int i = start;
        int hops = 0;
        while (i < msg.length) {
            int len = msg[i] & 0xFF;
            if (len == 0) return name.toString();
            if (len >= 0xC0) {
                if (hops++ >= maxHops) return name.toString();
                if (i + 1 >= msg.length) return name.toString();
                i = ((len & 0x3F) << 8) | (msg[i + 1] & 0xFF);
                continue;
            }
            if (i + 1 + len > msg.length) return name.toString();
            if (name.length() > 0) name.append('.');
            name.append(new String(msg, i + 1, len, StandardCharsets.US_ASCII));
            i += 1 + len;
        }
        return name.toString();
    }

    /** Resolves a host's first A record through one resolver, or null. */
    static String resolveA(String resolverIp, String host) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(header(0x4242, 0x0100, 1, 0, 0, 0));
        out.writeBytes(qname(host));
        out.writeBytes(QTAIL);
        byte[] query = out.toByteArray();
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(3000);
            socket.send(new DatagramPacket(query, query.length, InetAddress.getByName(resolverIp), 53));
            byte[] buf = new byte[1500];
            DatagramPacket resp = new DatagramPacket(buf, buf.length);
            socket.receive(resp);
            return firstAnswerIp(buf, resp.getLength());
        } catch (Exception ignored) {
            return null;
        }
    }

    /** Tries every resolver in turn; a polluted path may forge the first one. */
    public static String resolveAny(String host) {
        for (String resolver : RESOLVERS) {
            String ip = resolveA(resolver, host);
            if (ip != null && !ip.startsWith("0.")) return ip;
        }
        return null;
    }

    /** True for the ranges a local proxy hands out instead of a real answer. */
    private static boolean fakeIp(String ip) {
        return ip.startsWith("198.18.") || ip.startsWith("198.19.");
    }

    /** Every distinct address the resolvers offered, fake-ip values removed. */
    public static List<String> resolveCandidates(String host) {
        List<String> out = new ArrayList<>();
        for (String resolver : RESOLVERS) {
            String ip = resolveA(resolver, host);
            if (ip != null && !ip.startsWith("0.") && !fakeIp(ip) && !out.contains(ip)) out.add(ip);
        }
        return out;
    }

    /**
     * An address is only usable if it still answers the allowed name. GFW DNS
     * poisoning returns arbitrary public addresses, so a resolved value cannot be
     * trusted on its own: connecting there fails for every SNI, including the
     * control, which looks exactly like an address-level block.
     */
    public static boolean addressServesControl(String ip) {
        return tlsProbe(ip, tlsWire(TLS_CONTROL_HOST, "seed")) == Server.SERVER_HELLO;
    }

    /**
     * First address where the allowed name handshakes, or null when none does.
     * The hardcoded fallback is tried last so a poisoned answer cannot win.
     */
    public static String pickVerifiedAddress(String host) {
        List<String> candidates = resolveCandidates(host);
        if (!candidates.contains(TLS_IP_FALLBACK)) candidates.add(TLS_IP_FALLBACK);
        for (String ip : candidates) {
            if (addressServesControl(ip)) return ip;
        }
        return null;
    }

    /**
     * Sends one query and collects every reply inside the window. More than one
     * reply to a single query means an on-path injector raced the real resolver,
     * which is exactly how DNS poisoning shows up on this kind of path.
     */
    static List<Reply> poll(String resolverIp, byte[] query, int windowMs) {
        List<Reply> replies = new ArrayList<>();
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(DNS_POLL_SLICE_MS);
            socket.send(new DatagramPacket(query, query.length,
                    InetAddress.getByName(resolverIp), 53));
            long start = System.nanoTime();
            while (true) {
                int elapsed = (int) ((System.nanoTime() - start) / 1_000_000L);
                if (elapsed > windowMs) break;
                byte[] buf = new byte[1500];
                DatagramPacket resp = new DatagramPacket(buf, buf.length);
                try {
                    socket.receive(resp);
                } catch (SocketTimeoutException e) {
                    continue;
                }
                replies.add(Reply.answer(elapsed, answerIps(buf, resp.getLength())));
            }
        } catch (Exception e) {
            replies.add(Reply.failure(e.getClass().getSimpleName()));
        }
        return replies;
    }

    private static String firstAnswerIp(byte[] d, int n) {
        int an = ((d[6] & 0xFF) << 8) | (d[7] & 0xFF);
        int i = skipQuestion(d, n);
        for (int r = 0; r < an && i + 12 <= n; r++) {
            i = skipOwnerName(d, i, n);
            if (i + 10 > n) return null;
            int type = u16(d, i);
            int rdlen = u16(d, i + 8);
            i += 10;
            if (i + rdlen > n) return null;
            if (type == QTYPE_A && rdlen == 4) return ipv4(d, i);
            i += rdlen;
        }
        return null;
    }

    private static String answerIps(byte[] d, int n) {
        // A header-only reply is what a resolver returns on FORMERR; there is no
        // answer section to read.
        if (n <= DNS_HEADER_LEN) return "short";
        int an = ((d[6] & 0xFF) << 8) | (d[7] & 0xFF);
        int i = skipQuestion(d, n);
        StringBuilder ips = new StringBuilder();
        for (int r = 0; r < an && i + 12 <= n; r++) {
            i = skipOwnerName(d, i, n);
            if (i + 10 > n) break;
            int type = u16(d, i);
            int rdlen = u16(d, i + 8);
            i += 10;
            if (i + rdlen > n) break;
            if (type == QTYPE_A && rdlen == 4) {
                if (ips.length() > 0) ips.append(',');
                ips.append(ipv4(d, i));
            }
            i += rdlen;
        }
        return ips.length() == 0 ? "no-A" : ips.toString();
    }

    private static int skipQuestion(byte[] d, int n) {
        return skipOwnerName(d, DNS_HEADER_LEN, n) + 4; // QTYPE + QCLASS
    }

    private static int skipOwnerName(byte[] d, int i, int n) {
        while (i < n) {
            int len = d[i] & 0xFF;
            if (len == 0) return i + 1;
            if (len >= 0xC0) return Math.min(i + 2, n);
            i += 1 + len;
        }
        return n;
    }

    private static int u16(byte[] d, int i) { return ((d[i] & 0xFF) << 8) | (d[i + 1] & 0xFF); }

    private static String ipv4(byte[] d, int i) {
        return (d[i] & 0xFF) + "." + (d[i + 1] & 0xFF) + "." + (d[i + 2] & 0xFF) + "." + (d[i + 3] & 0xFF);
    }

    public static void runDns(List<Result> out, Progress progress) {
        int total = DNS_CASES + TLS_CASES;
        dnsCase(out, R.string.dns_seed_name, R.string.dns_seed_note, dnsSeed(), progress, 0, total);
        dnsCase(out, R.string.dns_fwd_name, R.string.dns_fwd_note, dnsForwardPointer(), progress, 1, total);
        dnsCase(out, R.string.dns_chain_name, R.string.dns_chain_note, dnsPointerChain(), progress, 2, total);
        dnsCase(out, R.string.dns_decoy_name, R.string.dns_decoy_note, dnsDecoySecondQuestion(), progress, 3, total);
        dnsCase(out, R.string.dns_fakeqd_name, R.string.dns_fakeqd_note, dnsFakeQdcount(), progress, 4, total);
        dnsCase(out, R.string.dns_ztc_name, R.string.dns_ztc_note, dnsFlagsZtc(), progress, 5, total);
        dnsCase(out, R.string.dns_counts_name, R.string.dns_counts_note, dnsFakeCounts(), progress, 6, total);
    }

    private static void dnsCase(List<Result> out, int nameRes, int noteRes, byte[] msg,
                                Progress progress, int index, int total) {
        if (progress != null) progress.onStep(index, total, nameRes);
        Result r = new Result(nameRes, noteRes);
        for (int i = 0; i < DNS_REPEATS; i++) {
            List<Reply> run = poll("8.8.8.8", msg, DNS_WINDOW_MS);
            if (run.isEmpty()) run = poll("9.9.9.9", msg, DNS_WINDOW_MS);
            r.runs++;
            if (run.size() > 1) r.injectedRuns++;
            r.replies.addAll(run);
        }

        boolean naive = dpiNaiveLiteral(msg);
        boolean pointerAware = dpiDepthLimited(msg);
        if (naive) r.dpi = Dpi.LITERAL_DETECTED;
        else if (pointerAware) r.dpi = Dpi.PARTIAL_POINTER;
        else r.dpi = Dpi.BOTH_BYPASS;
        out.add(r);
    }

    // ---------------- TLS ----------------

    private static byte[] u16(int v) { return new byte[] {(byte) (v >> 8), (byte) v}; }

    private static byte[] u24(int v) {
        return new byte[] {(byte) (v >> 16), (byte) (v >> 8), (byte) v};
    }

    private static byte[] cat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] p : parts) out.writeBytes(p);
        return out.toByteArray();
    }

    private static byte[] ext(int type, byte[] body) {
        return cat(u16(type), u16(body.length), body);
    }

    private static byte[] sniExt(String host) {
        byte[] name = host.getBytes(StandardCharsets.US_ASCII);
        byte[] entry = cat(new byte[] {0}, u16(name.length), name);
        return ext(0x0000, cat(u16(entry.length), entry));
    }

    /** Serializes one ClientHello; the variant picks which field gets rewritten. */
    static byte[] clientHello(String host, String variant) {
        ByteArrayOutputStream exts = new ByteArrayOutputStream();
        if (!variant.equals("nosni")) {
            String name = variant.equals("punycode") ? "xn--" + hex(host)
                    : variant.equals("trailing_dot") ? host + "."
                    : host;
            exts.writeBytes(sniExt(name));
        }
        exts.writeBytes(ext(0x002b, cat(new byte[] {2}, u16(0x0304))));
        exts.writeBytes(ext(0x000a, cat(u16(2), u16(0x001d))));
        exts.writeBytes(ext(0x000d, cat(u16(4), u16(0x0804), u16(0x0403))));
        ByteArrayOutputStream ks = new ByteArrayOutputStream();
        ks.writeBytes(u16(36));
        ks.writeBytes(u16(0x001d));
        ks.writeBytes(u16(32));
        for (int i = 0; i < 32; i++) ks.write(0x11);
        exts.writeBytes(ext(0x0033, ks.toByteArray()));
        if (variant.equals("pad")) {
            byte[] pad = new byte[PADDING_BYTES];
            exts.writeBytes(ext(0x0015, pad));
        }

        byte[] ciphers = {0x13, 0x01, 0x13, 0x02, 0x13, 0x03};
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.writeBytes(u16(0x0303));
        body.writeBytes(new byte[32]);
        body.write(0x20);
        for (int i = 0; i < 32; i++) body.write(0x22);
        body.writeBytes(u16(ciphers.length));
        body.writeBytes(ciphers);
        body.writeBytes(new byte[] {0x01, 0x00});
        body.writeBytes(u16(exts.size()));
        body.writeBytes(exts.toByteArray());

        byte[] b = body.toByteArray();
        return cat(new byte[] {0x01}, u24(b.length), b);
    }

    /** RFC 7685 padding, large enough that the record spans several TCP segments. */
    private static final int PADDING_BYTES = 4000;

    private static final int RECORD_HANDSHAKE = 0x16;
    private static final int VERSION_TLS10 = 0x0301;
    private static final int VERSION_TLS12 = 0x0303;

    private static byte[] record(int version, byte[] payload) {
        return cat(new byte[] {(byte) RECORD_HANDSHAKE, (byte) (version >> 8), (byte) version},
                u16(payload.length), payload);
    }

    /** Returns the bytes actually written to the socket for a variant. */
    static byte[] tlsWire(String host, String variant) {
        byte[] ch = clientHello(host, variant);
        switch (variant) {
            case "split_head":
                return cat(record(VERSION_TLS10, slice(ch, 0, 3)),
                        record(VERSION_TLS10, slice(ch, 3, ch.length)));
            case "split_sni": {
                int idx = indexOf(ch, host.getBytes(StandardCharsets.US_ASCII));
                int cut = idx < 0 ? ch.length / 2 : idx + 3;
                cut = Math.max(1, Math.min(cut, ch.length - 1));
                return cat(record(VERSION_TLS10, slice(ch, 0, cut)),
                        record(VERSION_TLS10, slice(ch, cut, ch.length)));
            }
            case "split_ver": {
                int cut = Math.max(1, ch.length / 2);
                return cat(record(VERSION_TLS12, slice(ch, 0, cut)),
                        record(VERSION_TLS10, slice(ch, cut, ch.length)));
            }
            default:
                return record(VERSION_TLS10, ch);
        }
    }

    private static byte[] slice(byte[] a, int from, int to) {
        byte[] out = new byte[to - from];
        System.arraycopy(a, from, out, 0, out.length);
        return out;
    }

    private static int indexOf(byte[] hay, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= hay.length; i++) {
            for (int j = 0; j < needle.length; j++) if (hay[i + j] != needle[j]) continue outer;
            return i;
        }
        return -1;
    }

    private static String hex(String host) {
        StringBuilder sb = new StringBuilder();
        for (byte b : host.getBytes(StandardCharsets.US_ASCII)) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    /** DPI simulation: only the first TLS record is inspected. */
    static boolean dpiFirstRecordOnly(byte[] wire) {
        if (wire.length < 5) return false;
        int end = Math.min(wire.length, 5 + u16(wire, 3));
        return containsAscii(wire, 5, end, TLS_HOST);
    }

    /** DPI simulation: reassembles every TLS record before matching. */
    static boolean dpiReassembleRecords(byte[] wire) {
        ByteArrayOutputStream all = new ByteArrayOutputStream();
        int i = 0;
        while (i + 5 <= wire.length) {
            int len = u16(wire, i + 3);
            if (i + 5 + len > wire.length) break;
            all.write(wire, i + 5, len);
            i += 5 + len;
        }
        byte[] asm = all.toByteArray();
        return containsAscii(asm, 0, asm.length, TLS_HOST);
    }

    private static boolean containsAscii(byte[] buf, int from, int to, String needle) {
        byte[] n = needle.getBytes(StandardCharsets.US_ASCII);
        outer:
        for (int i = from; i + n.length <= to; i++) {
            for (int j = 0; j < n.length; j++) if (buf[i + j] != n[j]) continue outer;
            return true;
        }
        return false;
    }

    /** Sends the wire bytes and classifies the reply. */
    static Server tlsProbe(String ip, byte[] wire) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(ip, 443), 6000);
            socket.setSoTimeout(6000);
            OutputStream os = socket.getOutputStream();
            os.write(wire);
            os.flush();
            InputStream is = socket.getInputStream();
            byte[] head = readExact(is, 5);
            if (head == null) return Server.parse("no-reply");
            int type = head[0] & 0xFF;
            if (type == 0x15) return Server.ALERT;
            if (type != RECORD_HANDSHAKE) return Server.NOT_TLS;
            byte[] payload = readExact(is, u16(head, 3));
            if (payload == null || payload.length == 0) return Server.TRUNCATED;
            int msgType = payload[0] & 0xFF;
            if (msgType == 2) return Server.SERVER_HELLO;
            if (msgType == 21) return Server.ALERT;
            return Server.ERROR;
        } catch (SocketTimeoutException e) {
            return Server.TIMEOUT;
        } catch (java.net.ConnectException e) {
            // ConnectException extends SocketException, so it must come first.
            return Server.CONNECT_FAILED;
        } catch (java.net.SocketException e) {
            // "Connection reset by peer" or a broken pipe after the ClientHello.
            return Server.RESET;
        } catch (Exception e) {
            return Server.ERROR;
        }
    }

    private static byte[] readExact(InputStream in, int n) throws IOException {
        byte[] buf = new byte[n];
        int off = 0;
        while (off < n) {
            int r = in.read(buf, off, n - off);
            if (r < 0) return off == 0 ? null : slice(buf, 0, off);
            off += r;
        }
        return buf;
    }

    public static void runTls(String ip, List<Result> out, Progress progress) {
        int base = DNS_CASES;
        int total = DNS_CASES + TLS_CASES;
        tlsCase(out, R.string.tls_seed_name, R.string.tls_seed_note, ip, "seed", progress, base, total);
        tlsCase(out, R.string.tls_split_head_name, R.string.tls_split_head_note, ip, "split_head", progress, base + 1, total);
        tlsCase(out, R.string.tls_split_sni_name, R.string.tls_split_sni_note, ip, "split_sni", progress, base + 2, total);
        tlsCase(out, R.string.tls_split_ver_name, R.string.tls_split_ver_note, ip, "split_ver", progress, base + 3, total);
        tlsCase(out, R.string.tls_nosni_name, R.string.tls_nosni_note, ip, "nosni", progress, base + 4, total);
        tlsCase(out, R.string.tls_dot_name, R.string.tls_dot_note, ip, "trailing_dot", progress, base + 5, total);
        tlsCase(out, R.string.tls_pad_name, R.string.tls_pad_note, ip, "pad", progress, base + 6, total);
        tlsCase(out, R.string.tls_puny_name, R.string.tls_puny_note, ip, "punycode", progress, base + 7, total);
        controlCase(out, ip, progress, base + 8, total);
    }

    /**
     * Sends an untouched ClientHello carrying an allowed hostname to the same
     * address. If this handshakes while the blocked baseline does not, the
     * middlebox is filtering on SNI and the evasion results mean something.
     */
    private static void controlCase(List<Result> out, String ip,
                                    Progress progress, int index, int total) {
        if (progress != null) progress.onStep(index, total, R.string.tls_control_name);
        Result r = new Result(R.string.tls_control_name, R.string.tls_control_note);
        r.control = true;
        r.server = tlsProbe(ip, tlsWire(TLS_CONTROL_HOST, "seed"));
        r.dpi = Dpi.BYPASS;
        out.add(r);
    }

    /** Compares the baseline against the variants; see {@link SniVerdict}. */
    public static SniVerdict sniVerdict(List<Result> tls) {
        if (tls.isEmpty()) return null;
        Result baseline = tls.get(0);
        Result control = null;
        for (Result r : tls) if (r.control) control = r;

        if (baseline.server == Server.SERVER_HELLO) return SniVerdict.NOT_BLOCKED;
        // Without a working control the refusal may be an address block, not SNI.
        if (control == null || control.server != Server.SERVER_HELLO) return SniVerdict.IP_BLOCKED;
        for (Result r : tls) {
            if (!r.control && r.server == Server.SERVER_HELLO) return SniVerdict.BYPASS_PROVEN;
        }
        return SniVerdict.BLOCKED_NO_EVASION;
    }

    /**
     * The evasion attempts only: the baseline (index 0) is the control group for
     * SNI blocking and the last entry is the allowed-name control probe, so
     * neither belongs in a per-variant rate.
     */
    public static List<Result> attempts(List<Result> tls) {
        List<Result> out = new ArrayList<>();
        for (int i = 1; i < tls.size(); i++) {
            Result r = tls.get(i);
            if (!r.control) out.add(r);
        }
        return out;
    }

    /**
     * Attempts that reached the server (a real TLS alert came back) without
     * handshaking. On a censored path this is the interesting middle ground:
     * the middlebox let the ClientHello through and the server declined it.
     */
    public static int reachedServerVariants(List<Result> tls) {
        int n = 0;
        for (Result r : attempts(tls)) if (r.server == Server.ALERT) n++;
        return n;
    }

    /** Attempts the server declined with a real TLS alert. */
    public static int alertVariants(List<Result> tls) { return reachedServerVariants(tls); }

    /** Attempts that were reset or dropped instead of reaching the server. */
    public static int blockedVariants(List<Result> tls) {
        int n = 0;
        for (Result r : attempts(tls)) {
            if (r.server == Server.RESET || r.server == Server.TIMEOUT
                    || r.server == Server.CONNECT_FAILED || r.server == Server.TRUNCATED) n++;
        }
        return n;
    }

    /** Attempts that handshook while the baseline did not. */
    public static int handshakeVariants(List<Result> tls) {
        int n = 0;
        for (Result r : attempts(tls)) if (r.server == Server.SERVER_HELLO) n++;
        return n;
    }

    /** Number of evasion attempts, baseline and control excluded. */
    public static int variantCount(List<Result> tls) {
        return attempts(tls).size();
    }

    private static void tlsCase(List<Result> out, int nameRes, int noteRes, String ip, String variant,
                                Progress progress, int index, int total) {
        if (progress != null) progress.onStep(index, total, nameRes);
        Result r = new Result(nameRes, noteRes);
        byte[] wire = tlsWire(TLS_HOST, variant);
        r.server = tlsProbe(ip, wire);
        // The blocklist holds the real hostname, so matching stays on it even
        // when the variant rewrites or removes the SNI.
        boolean first = dpiFirstRecordOnly(wire);
        boolean all = dpiReassembleRecords(wire);
        if (first) r.dpi = Dpi.FIRST_DETECTED;
        else if (all) r.dpi = Dpi.FIRST_BYPASS;
        else r.dpi = Dpi.BYPASS;
        out.add(r);
    }
}
