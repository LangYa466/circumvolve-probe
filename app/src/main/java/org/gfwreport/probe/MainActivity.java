package org.gfwreport.probe;

import android.app.Activity;
import android.graphics.Color;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.res.Resources;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.view.*;
import android.widget.*;

import java.util.*;

/**
 * Dark-only probe UI. Every packet is hand-built by {@link Probes} and sent
 * straight from this process; nothing here uses a proxy or a VPN.
 */
public class MainActivity extends Activity {

    private static final int BG = 0xFF0B0E13;
    private static final int SURFACE = 0xFF151A21;
    private static final int BORDER = 0xFF232A34;
    private static final int TEXT = 0xFFE6EDF3;
    private static final int MUTED = 0xFF8B949E;
    private static final int DETAIL = 0xFFB9C4D0;
    private static final int ACCENT = 0xFF4CC2FF;
    private static final int OK = 0xFF3FB950;
    private static final int WARN = 0xFFD29922;
    private static final int BAD = 0xFFF85149;
    private static final int BUTTON_TEXT = 0xFF04121C;

    private static final int CARD_PAD_H = 14;
    private static final int CARD_PAD_V = 12;
    private static final int CARD_GAP = 8;

    private Resources res;
    private LinearLayout list;
    private LinearLayout summaryCard;
    private LinearLayout emptyHint;
    private TextView summaryText;
    private Button runButton;
    private Button copyButton;
    private ProgressBar progress;
    private ProgressBar bar;
    private TextView progressLabel;
    /** Plain-text rendering of the last run, kept for the clipboard export. */
    private String lastReport;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        res = getResources();
        setTheme(R.style.AppTheme);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(BG);
        root.setPadding(dp(18), dp(18), dp(18), 0);

        TextView title = new TextView(this);
        title.setText(R.string.title);
        title.setTextColor(TEXT);
        title.setTextSize(24);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        root.addView(title);

        TextView sub = new TextView(this);
        sub.setText(R.string.subtitle);
        sub.setTextColor(MUTED);
        sub.setTextSize(12);
        sub.setPadding(0, dp(6), 0, dp(16));
        root.addView(sub);

        LinearLayout actionRow = new LinearLayout(this);
        actionRow.setOrientation(LinearLayout.HORIZONTAL);
        actionRow.setGravity(Gravity.CENTER_VERTICAL);

        runButton = new Button(this);
        runButton.setText(R.string.action_run);
        runButton.setAllCaps(false);
        runButton.setTextSize(15);
        runButton.setTextColor(BUTTON_TEXT);
        runButton.setTypeface(Typeface.DEFAULT_BOLD);
        GradientDrawable btnBg = new GradientDrawable();
        btnBg.setColor(ACCENT);
        btnBg.setCornerRadius(dp(10));
        runButton.setBackground(btnBg);
        runButton.setOnClickListener(v -> runAll());
        actionRow.addView(runButton, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        copyButton = new Button(this);
        copyButton.setText(R.string.action_copy);
        copyButton.setAllCaps(false);
        copyButton.setTextSize(13);
        copyButton.setTextColor(TEXT);
        copyButton.setVisibility(View.GONE);
        GradientDrawable copyBg = new GradientDrawable();
        copyBg.setColor(withAlpha(BORDER, 0x66));
        copyBg.setCornerRadius(dp(10));
        copyBg.setStroke(dp(1), BORDER);
        copyButton.setBackground(copyBg);
        copyButton.setOnClickListener(v -> copyReport());
        LinearLayout.LayoutParams clp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        clp.leftMargin = dp(10);
        actionRow.addView(copyButton, clp);

        progress = new ProgressBar(this);
        progress.setVisibility(View.GONE);
        LinearLayout.LayoutParams plp = new LinearLayout.LayoutParams(dp(28), dp(28));
        plp.leftMargin = dp(14);
        actionRow.addView(progress, plp);
        root.addView(actionRow);

        // Determinate bar plus the name of the case in flight.
        bar = new ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal);
        bar.setMax(100);
        bar.setVisibility(View.GONE);
        LinearLayout.LayoutParams blp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(6));
        blp.topMargin = dp(14);
        root.addView(bar, blp);

        progressLabel = new TextView(this);
        progressLabel.setTextColor(MUTED);
        progressLabel.setTextSize(11);
        progressLabel.setTypeface(Typeface.MONOSPACE);
        progressLabel.setVisibility(View.GONE);
        progressLabel.setPadding(0, dp(6), 0, 0);
        root.addView(progressLabel);

        summaryCard = new LinearLayout(this);
        summaryCard.setOrientation(LinearLayout.VERTICAL);
        summaryCard.setVisibility(View.GONE);
        summaryCard.setBackground(cardBackground());
        summaryCard.setPadding(dp(16), dp(14), dp(16), dp(14));
        LinearLayout.LayoutParams slp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        slp.topMargin = dp(16);
        root.addView(summaryCard, slp);

        summaryText = new TextView(this);
        summaryText.setTextColor(TEXT);
        summaryText.setTextSize(13);
        summaryText.setLineSpacing(dp(4), 1f);
        summaryCard.addView(summaryText);

        emptyHint = new LinearLayout(this);
        emptyHint.setOrientation(LinearLayout.VERTICAL);
        emptyHint.setGravity(Gravity.CENTER);
        emptyHint.setPadding(0, dp(70), 0, 0);
        TextView hint = new TextView(this);
        hint.setText(R.string.empty_hint);
        hint.setTextColor(0xFF4A5260);
        hint.setTextSize(13);
        hint.setGravity(Gravity.CENTER);
        emptyHint.addView(hint);
        root.addView(emptyHint);

        ScrollView scroll = new ScrollView(this);
        scroll.setClipToPadding(false);
        scroll.setPadding(0, dp(12), 0, dp(24));
        list = new LinearLayout(this);
        list.setOrientation(LinearLayout.VERTICAL);
        scroll.addView(list);
        root.addView(scroll, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));

        setContentView(root);
    }

    private int dp(int v) {
        return Math.round(v * getResources().getDisplayMetrics().density);
    }

    private GradientDrawable cardBackground() {
        GradientDrawable bg = new GradientDrawable();
        bg.setColor(SURFACE);
        bg.setCornerRadius(dp(12));
        bg.setStroke(dp(1), BORDER);
        return bg;
    }

    private void runAll() {
        runButton.setEnabled(false);
        runButton.setText(R.string.action_running);
        progress.setVisibility(View.VISIBLE);
        list.removeAllViews();
        summaryCard.setVisibility(View.GONE);
        emptyHint.setVisibility(View.GONE);
        copyButton.setVisibility(View.GONE);
        bar.setProgress(0);
        bar.setVisibility(View.VISIBLE);
        progressLabel.setVisibility(View.VISIBLE);
        lastReport = null;

        new Thread(() -> {
            List<Probes.Result> dns = new ArrayList<>();
            List<Probes.Result> tls = new ArrayList<>();

            // A polluted answer is just some public address, so a resolved value
            // is accepted only when the allowed name still handshakes there.
            String serverIp = Probes.pickVerifiedAddress(Probes.TLS_HOST);
            boolean verified = serverIp != null;
            if (!verified) serverIp = Probes.TLS_IP_FALLBACK;
            String hostNote = verified
                    ? res.getString(R.string.host_verified, Probes.TLS_HOST, serverIp)
                    : res.getString(R.string.host_unverified, Probes.TLS_HOST, serverIp);

            // Same callback for both phases: the counters span the whole run.
            Probes.Progress onStep = (done, total, labelRes) -> runOnUiThread(() -> {
                bar.setMax(total);
                bar.setProgress(done);
                progressLabel.setText(res.getString(R.string.progress_step,
                        done + 1, total, res.getString(labelRes)));
            });

            Probes.runDns(dns, onStep);
            Probes.runTls(serverIp, tls, onStep);

            runOnUiThread(() -> render(dns, tls, hostNote));
        }, "probe").start();
    }

    private void render(List<Probes.Result> dns, List<Probes.Result> tls, String hostNote) {
        addSection(res.getString(R.string.section_dns));
        for (Probes.Result r : dns) addDnsCard(r);

        addSection(res.getString(R.string.section_tls_with_host, hostNote));
        for (Probes.Result r : tls) addTlsCard(r);

        int injected = 0, dnsBypass = 0, proxied = 0;
        for (Probes.Result r : dns) {
            if (r.injected()) injected++;
            if (r.bypassed()) dnsBypass++;
            if (r.proxied()) proxied++;
        }
        // Count over the evasion attempts only: the baseline and the allowed-name
        // control are reference points, not results.
        int tlsBypass = 0, hello = 0;
        for (Probes.Result r : Probes.attempts(tls)) {
            if (r.bypassed()) tlsBypass++;
            if (r.server.handshakeOk()) hello++;
        }
        int variants = Probes.variantCount(tls);

        String suffix = proxied > 0 ? res.getString(R.string.summary_proxied_suffix) : "";
        summaryText.setText(res.getString(R.string.summary,
                injected, dns.size(), dnsBypass, dns.size(), suffix,
                hello, variants, tlsBypass, variants)
                + "\n" + res.getString(R.string.sni_summary,
                        Probes.handshakeVariants(tls), Probes.alertVariants(tls),
                        Probes.blockedVariants(tls), Probes.variantCount(tls))
                + "\n" + sniVerdictText(tls));
        summaryCard.setVisibility(View.VISIBLE);
        runButton.setEnabled(true);
        runButton.setText(R.string.action_rerun);
        progress.setVisibility(View.GONE);
        bar.setVisibility(View.GONE);
        progressLabel.setVisibility(View.GONE);
        copyButton.setVisibility(View.VISIBLE);
        lastReport = buildReport(dns, tls, hostNote);
    }

    /**
     * Plain-text dump of one full run, meant to be pasted into a bug report.
     * Every line mirrors what the cards show, with the enums spelled out.
     */
    private String buildReport(List<Probes.Result> dns, List<Probes.Result> tls, String hostNote) {
        StringBuilder sb = new StringBuilder();
        sb.append(res.getString(R.string.title)).append('\n');
        sb.append("app ").append(BuildConfig.VERSION_NAME)
                .append("  ·  android ").append(android.os.Build.VERSION.RELEASE)
                .append(" (sdk ").append(android.os.Build.VERSION.SDK_INT).append(")\n");
        sb.append("device ").append(android.os.Build.MANUFACTURER).append(' ')
                .append(android.os.Build.MODEL).append('\n');
        sb.append("blocked host ").append(Probes.BLOCKED).append('\n');
        sb.append("tls host ").append(Probes.TLS_HOST).append('\n');
        sb.append("locale ").append(res.getConfiguration().getLocales().get(0)).append("\n\n");

        int injected = 0, dnsBypass = 0, proxied = 0;
        for (Probes.Result r : dns) {
            if (r.injected()) injected++;
            if (r.bypassed()) dnsBypass++;
            if (r.proxied()) proxied++;
        }
        // Count over the evasion attempts only: the baseline and the allowed-name
        // control are reference points, not results.
        int tlsBypass = 0, hello = 0;
        for (Probes.Result r : Probes.attempts(tls)) {
            if (r.bypassed()) tlsBypass++;
            if (r.server.handshakeOk()) hello++;
        }
        int variants = Probes.variantCount(tls);

        sb.append("== ").append(res.getString(R.string.section_dns)).append(" ==\n");
        sb.append("injected ").append(injected).append('/').append(dns.size())
                .append("  dpi-bypass ").append(dnsBypass).append('/').append(dns.size())
                .append("  proxied ").append(proxied).append('/').append(dns.size())
                .append("\n\n");
        for (Probes.Result r : dns) appendReportCase(sb, r);

        sb.append("== ").append(res.getString(R.string.section_tls_with_host, hostNote)).append(" ==\n");
        sb.append("server-hello ").append(hello).append('/').append(variants)
                .append("  first-record-bypass ").append(tlsBypass).append('/').append(variants)
                .append('\n');
        sb.append(res.getString(R.string.sni_summary,
                Probes.handshakeVariants(tls), Probes.alertVariants(tls),
                Probes.blockedVariants(tls), Probes.variantCount(tls))).append('\n');
        sb.append("verdict ").append(sniVerdictText(tls)).append("\n\n");
        for (Probes.Result r : tls) appendReportCase(sb, r);

        return sb.toString();
    }

    private void appendReportCase(StringBuilder sb, Probes.Result r) {
        sb.append("- ").append(res.getString(r.nameRes)).append('\n');
        sb.append("    note   ").append(r.control
                ? res.getString(r.noteRes, Probes.TLS_CONTROL_HOST)
                : res.getString(r.noteRes)).append('\n');
        sb.append("    dpi    ").append(dpiLabel(r.dpi)).append('\n');
        if (r.server != Probes.Server.NOT_PROBED) {
            sb.append("    server ").append(serverLabel(r.server)).append('\n');
        }
        if (r.server != Probes.Server.NOT_PROBED) {
            // TLS cases carry the outcome in `server`; they never poll DNS.
            sb.append('\n');
            return;
        }
        if (r.replies.isEmpty()) {
            sb.append("    reply  ").append(res.getString(R.string.reply_none)).append('\n');
        } else {
            sb.append("    reply  ").append(rateLabel(r))
                    .append(r.injectedEveryRun() ? "  <-- INJECTED every run"
                            : r.injected() ? "  <-- INJECTED intermittently" : "")
                    .append(r.proxied() ? "  <-- proxied" : "").append('\n');
            for (Probes.Reply rep : r.replies) {
                if (rep.error != null) {
                    sb.append("           ").append(res.getString(R.string.reply_err, rep.error)).append('\n');
                } else {
                    sb.append("           ").append(res.getString(R.string.reply_line,
                            rep.elapsedMs, rep.ips)).append('\n');
                }
            }
        }
        sb.append('\n');
    }

    private void copyReport() {
        String text = lastReport;
        if (text == null || text.isEmpty()) {
            toast(res.getString(R.string.action_copy_empty));
            return;
        }
        ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        cm.setPrimaryClip(ClipData.newPlainText(res.getString(R.string.title), text));
        toast(res.getString(R.string.action_copied));
    }

    private void toast(String message) {
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show();
    }

    /** One line stating whether this run actually proved an SNI bypass. */
    private String sniVerdictText(List<Probes.Result> tls) {
        Probes.SniVerdict v = Probes.sniVerdict(tls);
        if (v == null) return res.getString(R.string.sni_unknown);
        switch (v) {
            case NOT_BLOCKED: return res.getString(R.string.sni_not_blocked);
            case BYPASS_PROVEN:
                return res.getString(R.string.sni_bypass_proven,
                        Probes.handshakeVariants(tls), Probes.variantCount(tls));
            case IP_BLOCKED: return res.getString(R.string.sni_ip_blocked);
            case NO_VERIFIED_ADDRESS: return res.getString(R.string.sni_no_address);
            default: return res.getString(R.string.sni_blocked_no_evasion);
        }
    }

    private void addSection(String label) {
        TextView tv = new TextView(this);
        tv.setText(label);
        tv.setTextColor(ACCENT);
        tv.setTextSize(11);
        tv.setTypeface(Typeface.DEFAULT_BOLD);
        tv.setLetterSpacing(0.08f);
        tv.setPadding(dp(4), dp(14), 0, dp(8));
        list.addView(tv);
    }

    private void addDnsCard(Probes.Result r) {
        int color;
        if (r.injected()) color = BAD;
        else if (r.proxied()) color = WARN;
        else if (r.answered()) color = OK;
        else color = MUTED;
        addCard(r, dnsBadge(r), color, replyLines(r), null);
    }

    private void addTlsCard(Probes.Result r) {
        int color;
        switch (r.server) {
            case SERVER_HELLO: color = OK; break;
            case NOT_PROBED: color = MUTED; break;
            default: color = BAD; break;
        }
        // TLS cases have no DNS replies; the server outcome is the whole result.
        addCard(r, tlsBadge(r), color, null, serverLabel(r.server));
    }

    private String dnsBadge(Probes.Result r) {
        if (r.injectedEveryRun()) return res.getString(R.string.badge_injected_all);
        if (r.injected()) return res.getString(R.string.badge_injected);
        if (r.proxied()) return res.getString(R.string.badge_proxied);
        if (r.answered()) return res.getString(R.string.badge_answered);
        return res.getString(R.string.badge_none);
    }

    private String tlsBadge(Probes.Result r) {
        switch (r.server) {
            case SERVER_HELLO: return res.getString(R.string.badge_handshake);
            case ALERT: return res.getString(R.string.badge_rejected);
            case NOT_PROBED: return res.getString(R.string.badge_dash);
            default: return serverLabel(r.server);
        }
    }

    /** One line per reply, or the single reason a query produced none. */
    private String replyLines(Probes.Result r) {
        if (r.replies.isEmpty()) return res.getString(R.string.reply_none);
        StringBuilder sb = new StringBuilder();
        if (r.runs > 0) sb.append(rateLabel(r)).append('\n');
        for (Probes.Reply rep : r.replies) {
            if (sb.length() > 0) sb.append('\n');
            if (rep.error != null) {
                sb.append(res.getString(R.string.reply_err, rep.error));
            } else {
                sb.append(res.getString(R.string.reply_line, rep.elapsedMs, rep.ips));
            }
        }
        return sb.toString();
    }

    /** "2/3 runs injected", and the clean/all-run special cases. */
    private String rateLabel(Probes.Result r) {
        if (r.injectedRuns == 0) return res.getString(R.string.reply_rate_clean, r.runs);
        if (r.injectedRuns == r.runs) return res.getString(R.string.reply_rate_all);
        return res.getString(R.string.reply_rate, r.injectedRuns, r.runs);
    }

    private String dpiLabel(Probes.Dpi dpi) {
        if (dpi == null) return res.getString(R.string.badge_dash);
        switch (dpi) {
            case BOTH_BYPASS: return res.getString(R.string.dpi_both_bypass);
            case LITERAL_DETECTED: return res.getString(R.string.dpi_literal_detected);
            case PARTIAL_POINTER: return res.getString(R.string.dpi_pointer_aware);
            case FIRST_DETECTED: return res.getString(R.string.dpi_first_record);
            case FIRST_BYPASS: return res.getString(R.string.dpi_partial);
            default: return res.getString(R.string.dpi_full);
        }
    }

    private static int dpiColor(Probes.Dpi dpi) {
        if (dpi == null) return MUTED;
        switch (dpi) {
            case BOTH_BYPASS:
            case BYPASS:
                return OK;
            case PARTIAL_POINTER:
            case FIRST_BYPASS:
                return WARN;
            default:
                return BAD;
        }
    }

    /** Human name for a server outcome; the enums alone are not translatable. */
    private String serverLabel(Probes.Server server) {
        switch (server) {
            case SERVER_HELLO: return res.getString(R.string.badge_handshake);
            case ALERT: return res.getString(R.string.badge_rejected);
            case RESET: return res.getString(R.string.server_reset);
            case CONNECT_FAILED: return res.getString(R.string.server_connect_failed);
            case TIMEOUT: return res.getString(R.string.server_timeout);
            case NOT_TLS: return res.getString(R.string.server_not_tls);
            case TRUNCATED: return res.getString(R.string.server_truncated);
            case ERROR: return res.getString(R.string.server_error);
            default: return res.getString(R.string.badge_dash);
        }
    }

    private void addCard(Probes.Result r, String badge, int badgeColor,
                         String repliesText, String serverText) {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackground(cardBackground());
        card.setPadding(dp(CARD_PAD_H), dp(CARD_PAD_V), dp(CARD_PAD_H), dp(CARD_PAD_V));

        LinearLayout head = new LinearLayout(this);
        head.setOrientation(LinearLayout.HORIZONTAL);
        head.setGravity(Gravity.CENTER_VERTICAL);

        TextView title = new TextView(this);
        title.setText(r.nameRes);
        title.setTextColor(TEXT);
        title.setTextSize(14);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        head.addView(title, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        head.addView(chip(badge, badgeColor));
        card.addView(head);

        CharSequence note = r.control
                ? res.getString(r.noteRes, Probes.TLS_CONTROL_HOST)
                : res.getString(r.noteRes);
        addLine(card, note, MUTED, false, dp(3), dp(6));
        if (repliesText != null) addLine(card, repliesText, DETAIL, true, 0, 0);
        if (serverText != null) {
            addLine(card, res.getString(R.string.label_server) + "  " + serverText, DETAIL, true, 0, 0);
        }
        addLine(card, res.getString(R.string.label_dpi) + "  " + dpiLabel(r.dpi),
                dpiColor(r.dpi), true, 0, 0);

        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.bottomMargin = dp(CARD_GAP);
        list.addView(card, lp);
    }

    private void addLine(LinearLayout card, CharSequence text, int color, boolean mono,
                         int padTop, int padBottom) {
        TextView tv = new TextView(this);
        tv.setText(text);
        tv.setTextColor(color);
        tv.setTextSize(11);
        if (mono) tv.setTypeface(Typeface.MONOSPACE);
        tv.setLineSpacing(dp(2), 1f);
        tv.setPadding(0, padTop, 0, padBottom);
        card.addView(tv);
    }

    private TextView chip(String text, int color) {
        TextView tv = new TextView(this);
        tv.setText(text);
        tv.setTextColor(color);
        tv.setTextSize(10);
        tv.setTypeface(Typeface.DEFAULT_BOLD);
        GradientDrawable bg = new GradientDrawable();
        bg.setColor(withAlpha(color, 0x22));
        bg.setCornerRadius(dp(6));
        bg.setStroke(dp(1), withAlpha(color, 0x55));
        tv.setBackground(bg);
        tv.setPadding(dp(8), dp(3), dp(8), dp(3));
        return tv;
    }

    private static int withAlpha(int color, int alpha) {
        return (color & 0x00FFFFFF) | (alpha << 24);
    }
}
