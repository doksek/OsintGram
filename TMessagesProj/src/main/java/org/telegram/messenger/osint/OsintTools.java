package org.telegram.messenger.osint;

import android.app.Activity;
import android.content.ContentValues;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import android.provider.MediaStore;
import android.text.TextUtils;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.telegram.messenger.AndroidUtilities;
import org.telegram.messenger.ChatObject;
import org.telegram.messenger.FileLoader;
import org.telegram.messenger.FileLog;
import org.telegram.messenger.LocaleController;
import org.telegram.messenger.MessageObject;
import org.telegram.messenger.MessagesController;
import org.telegram.messenger.R;
import org.telegram.messenger.UserObject;
import org.telegram.tgnet.TLRPC;
import org.telegram.ui.ActionBar.AlertDialog;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TimeZone;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * OsintGram: OSINT tools for messages and chats.
 * Everything runs locally on the device; nothing is sent to third-party servers.
 */
public final class OsintTools {

    private OsintTools() {
    }

    private static final String DOWNLOAD_SUBDIR = "OsintGram";

    // ---------------------------------------------------------------------
    // Indicators of compromise / investigation leads
    // ---------------------------------------------------------------------

    public static final class Indicator {
        public final String type;
        public final String value;

        Indicator(String type, String value) {
            this.type = type;
            this.value = value;
        }
    }

    private static final Pattern URL = Pattern.compile("(?i)\\b(?:https?://|www\\.|t\\.me/|telegram\\.me/)[^\\s<>\"'()\\[\\]{}]+");
    private static final Pattern MENTION = Pattern.compile("(?<![\\w@/])@([A-Za-z][A-Za-z0-9_]{3,31})\\b");
    private static final Pattern EMAIL = Pattern.compile("\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b");
    private static final Pattern BTC = Pattern.compile("\\b(?:bc1[a-z0-9]{25,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\\b");
    private static final Pattern EVM = Pattern.compile("\\b0x[a-fA-F0-9]{40}\\b");
    private static final Pattern TRON = Pattern.compile("\\bT[1-9A-HJ-NP-Za-km-z]{33}\\b");
    private static final Pattern TON = Pattern.compile("(?<![A-Za-z0-9_-])(?:EQ|UQ)[A-Za-z0-9_-]{46}(?![A-Za-z0-9_-])");

    /** Extracts links, mentions, e-mails and crypto wallets from a piece of text. */
    public static List<Indicator> extractIndicators(String text) {
        ArrayList<Indicator> out = new ArrayList<>();
        if (TextUtils.isEmpty(text)) {
            return out;
        }
        addAll(out, "url", URL, text, 0);
        addAll(out, "mention", MENTION, text, 0);
        addAll(out, "email", EMAIL, text, 0);
        addAll(out, "wallet_btc", BTC, text, 0);
        addAll(out, "wallet_evm", EVM, text, 0);
        addAll(out, "wallet_tron", TRON, text, 0);
        addAll(out, "wallet_ton", TON, text, 0);
        return out;
    }

    private static void addAll(List<Indicator> out, String type, Pattern p, String text, int group) {
        Matcher m = p.matcher(text);
        while (m.find()) {
            String v = m.group(group);
            if (type.equals("url")) {
                v = trimTrailingPunctuation(v);
            }
            if (type.equals("mention") && v.startsWith("@") == false) {
                v = "@" + v;
            }
            out.add(new Indicator(type, v));
        }
    }

    private static String trimTrailingPunctuation(String v) {
        int end = v.length();
        while (end > 0 && ".,;:!?»".indexOf(v.charAt(end - 1)) >= 0) {
            end--;
        }
        return v.substring(0, end);
    }

    /** Text + hidden links (text_url entities) of a message. */
    private static List<Indicator> indicatorsOf(TLRPC.Message msg) {
        List<Indicator> list = extractIndicators(msg.message);
        if (msg.entities != null) {
            for (TLRPC.MessageEntity e : msg.entities) {
                if (e instanceof TLRPC.TL_messageEntityTextUrl && !TextUtils.isEmpty(e.url)) {
                    list.add(new Indicator("url_hidden", e.url));
                }
            }
        }
        return list;
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    public static String utc(long unixSeconds) {
        if (unixSeconds <= 0) {
            return "-";
        }
        SimpleDateFormat f = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss 'UTC'", Locale.US);
        f.setTimeZone(TimeZone.getTimeZone("UTC"));
        return f.format(new Date(unixSeconds * 1000L));
    }

    private static String fileStamp() {
        SimpleDateFormat f = new SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US);
        f.setTimeZone(TimeZone.getTimeZone("UTC"));
        return f.format(new Date());
    }

    public static String sha256(String s) {
        return sha256(s == null ? new byte[0] : s.getBytes(StandardCharsets.UTF_8));
    }

    public static String sha256(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest(data);
            StringBuilder sb = new StringBuilder(d.length * 2);
            for (byte b : d) {
                sb.append(String.format(Locale.US, "%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            return "";
        }
    }

    private static String peerName(int account, long peerId) {
        MessagesController mc = MessagesController.getInstance(account);
        if (peerId > 0) {
            TLRPC.User u = mc.getUser(peerId);
            if (u == null) {
                return "user " + peerId;
            }
            String name = UserObject.getUserName(u);
            String un = UserObject.getPublicUsername(u);
            return name + (un != null ? " (@" + un + ")" : "") + " [id " + peerId + "]";
        } else if (peerId < 0) {
            TLRPC.Chat c = mc.getChat(-peerId);
            if (c == null) {
                return "chat " + (-peerId);
            }
            String un = ChatObject.getPublicUsername(c);
            return c.title + (un != null ? " (@" + un + ")" : "") + " [id " + (-peerId) + "]";
        }
        return "-";
    }

    /** Public link to a message in a channel / supergroup, or null. */
    public static String messageLink(int account, long dialogId, int messageId) {
        if (dialogId >= 0 || messageId <= 0) {
            return null;
        }
        TLRPC.Chat chat = MessagesController.getInstance(account).getChat(-dialogId);
        if (chat == null || !ChatObject.isChannel(chat)) {
            return null;
        }
        String un = ChatObject.getPublicUsername(chat);
        if (un != null) {
            return "https://t.me/" + un + "/" + messageId;
        }
        return "https://t.me/c/" + chat.id + "/" + messageId;
    }

    // ---------------------------------------------------------------------
    // Passport of a user / chat
    // ---------------------------------------------------------------------

    private static void appendUserPassport(StringBuilder sb, TLRPC.User u) {
        sb.append("ID: ").append(u.id).append('\n');
        sb.append("Name: ").append(UserObject.getUserName(u)).append('\n');
        String un = UserObject.getPublicUsername(u);
        sb.append("Username: ").append(un != null ? "@" + un : "-").append('\n');
        if (u.usernames != null && u.usernames.size() > 1) {
            sb.append("All usernames:");
            for (TLRPC.TL_username x : u.usernames) {
                sb.append(" @").append(x.username).append(x.active ? "" : " (inactive)");
            }
            sb.append('\n');
        }
        if (u.photo != null && u.photo.dc_id != 0) {
            sb.append("DC (by profile photo): ").append(u.photo.dc_id).append('\n');
        }
        StringBuilder flags = new StringBuilder();
        if (u.bot) flags.append("bot ");
        if (u.verified) flags.append("verified ");
        if (u.premium) flags.append("premium ");
        if (u.scam) flags.append("SCAM ");
        if (u.fake) flags.append("FAKE ");
        if (u.deleted) flags.append("deleted ");
        if (u.support) flags.append("support ");
        if (u.restricted) flags.append("restricted ");
        sb.append("Flags: ").append(flags.length() > 0 ? flags.toString().trim() : "-").append('\n');
        if (u.bot && u.bot_active_users > 0) {
            sb.append("Bot monthly users: ").append(u.bot_active_users).append('\n');
        }
    }

    private static void appendChatPassport(StringBuilder sb, TLRPC.Chat c) {
        sb.append("ID: ").append(c.id).append(" (dialog id ").append(-c.id).append(")\n");
        sb.append("Title: ").append(c.title).append('\n');
        String un = ChatObject.getPublicUsername(c);
        sb.append("Username: ").append(un != null ? "@" + un : "-").append('\n');
        String type = c.broadcast ? "channel" : c.megagroup ? (c.forum ? "forum supergroup" : "supergroup") : (ChatObject.isChannel(c) ? "channel" : "group");
        sb.append("Type: ").append(type).append('\n');
        if (c.participants_count > 0) {
            sb.append("Members: ").append(c.participants_count).append('\n');
        }
        if (c.date > 0) {
            sb.append("Date (creation or your join): ").append(utc(c.date)).append('\n');
        }
        if (c.photo != null && c.photo.dc_id != 0) {
            sb.append("DC (by photo): ").append(c.photo.dc_id).append('\n');
        }
        StringBuilder flags = new StringBuilder();
        if (c.verified) flags.append("verified ");
        if (c.scam) flags.append("SCAM ");
        if (c.fake) flags.append("FAKE ");
        if (c.signatures) flags.append("signatures ");
        if (c.noforwards) flags.append("noforwards ");
        if (c.restricted) flags.append("restricted ");
        sb.append("Flags: ").append(flags.length() > 0 ? flags.toString().trim() : "-").append('\n');
    }

    private static void appendPeerPassport(StringBuilder sb, int account, long peerId) {
        MessagesController mc = MessagesController.getInstance(account);
        if (peerId > 0) {
            TLRPC.User u = mc.getUser(peerId);
            if (u != null) {
                appendUserPassport(sb, u);
            } else {
                sb.append("ID: ").append(peerId).append(" (user not loaded)\n");
            }
        } else if (peerId < 0) {
            TLRPC.Chat c = mc.getChat(-peerId);
            if (c != null) {
                appendChatPassport(sb, c);
            } else {
                sb.append("ID: ").append(-peerId).append(" (chat not loaded)\n");
            }
        }
    }

    // ---------------------------------------------------------------------
    // Message report
    // ---------------------------------------------------------------------

    public static String buildMessageReport(int account, MessageObject mo) {
        TLRPC.Message m = mo.messageOwner;
        StringBuilder sb = new StringBuilder();
        long dialogId = mo.getDialogId();

        sb.append("== MESSAGE ==\n");
        sb.append("Message ID: ").append(m.id).append('\n');
        sb.append("Chat: ").append(peerName(account, dialogId)).append('\n');
        String link = messageLink(account, dialogId, m.id);
        if (link != null) {
            sb.append("Link: ").append(link).append('\n');
        }
        sb.append("Date: ").append(utc(m.date)).append('\n');
        if (m.edit_date > 0) {
            sb.append("Edited: ").append(utc(m.edit_date)).append('\n');
        }
        if (m.views > 0) {
            sb.append("Views: ").append(m.views).append('\n');
        }
        if (m.forwards > 0) {
            sb.append("Forwards: ").append(m.forwards).append('\n');
        }
        if (!TextUtils.isEmpty(m.post_author)) {
            sb.append("Post author signature: ").append(m.post_author).append('\n');
        }
        if (m.grouped_id != 0) {
            sb.append("Album (grouped_id): ").append(m.grouped_id).append('\n');
        }
        if (m.via_bot_id != 0) {
            sb.append("Via bot: ").append(peerName(account, m.via_bot_id)).append('\n');
        }

        long senderId = m.from_id != null ? MessageObject.getPeerId(m.from_id) : dialogId;
        sb.append("\n== SENDER ==\n");
        appendPeerPassport(sb, account, senderId);

        if (m.fwd_from != null) {
            TLRPC.MessageFwdHeader f = m.fwd_from;
            sb.append("\n== FORWARDED FROM ==\n");
            if (f.from_id != null) {
                long origin = MessageObject.getPeerId(f.from_id);
                appendPeerPassport(sb, account, origin);
                if (f.channel_post != 0) {
                    sb.append("Original post ID: ").append(f.channel_post).append('\n');
                    String origLink = messageLink(account, origin, f.channel_post);
                    if (origLink != null) {
                        sb.append("Original link: ").append(origLink).append('\n');
                    }
                }
            } else if (!TextUtils.isEmpty(f.from_name)) {
                sb.append("Name (hidden account): ").append(f.from_name).append('\n');
            }
            if (!TextUtils.isEmpty(f.post_author)) {
                sb.append("Original author signature: ").append(f.post_author).append('\n');
            }
            sb.append("Original date: ").append(utc(f.date)).append('\n');
            if (f.saved_from_peer != null) {
                sb.append("Saved from: ").append(peerName(account, MessageObject.getPeerId(f.saved_from_peer)));
                if (f.saved_from_msg_id != 0) {
                    sb.append(", message ").append(f.saved_from_msg_id);
                }
                sb.append('\n');
            }
        }

        appendMedia(sb, m);

        List<Indicator> ind = indicatorsOf(m);
        if (!ind.isEmpty()) {
            sb.append("\n== INDICATORS ==\n");
            for (Indicator i : ind) {
                sb.append(i.type).append(": ").append(i.value).append('\n');
            }
        }

        sb.append("\n== INTEGRITY ==\n");
        sb.append("Text SHA-256: ").append(sha256(m.message)).append('\n');
        sb.append("Report generated: ").append(utc(System.currentTimeMillis() / 1000)).append(" by OsintGram\n");
        return sb.toString();
    }

    private static void appendMedia(StringBuilder sb, TLRPC.Message m) {
        if (m.media == null) {
            return;
        }
        TLRPC.Document doc = m.media.document;
        TLRPC.Photo photo = m.media.photo;
        if (doc == null && photo == null) {
            return;
        }
        sb.append("\n== MEDIA ==\n");
        if (doc != null) {
            sb.append("Type: document\n");
            String name = FileLoader.getDocumentFileName(doc);
            if (!TextUtils.isEmpty(name)) {
                sb.append("File name: ").append(name).append('\n');
            }
            sb.append("MIME: ").append(doc.mime_type).append('\n');
            sb.append("Size: ").append(AndroidUtilities.formatFileSize(doc.size)).append(" (").append(doc.size).append(" bytes)\n");
            sb.append("File ID: ").append(doc.id).append(", DC ").append(doc.dc_id).append('\n');
        } else {
            sb.append("Type: photo\n");
            sb.append("Photo ID: ").append(photo.id).append(", DC ").append(photo.dc_id).append('\n');
        }
    }

    private static JSONObject buildMessageJson(int account, MessageObject mo, String report) throws JSONException {
        TLRPC.Message m = mo.messageOwner;
        long dialogId = mo.getDialogId();
        JSONObject o = new JSONObject();
        o.put("tool", "OsintGram");
        o.put("captured_at_utc", utc(System.currentTimeMillis() / 1000));
        o.put("dialog_id", dialogId);
        o.put("chat", peerName(account, dialogId));
        o.put("message_id", m.id);
        String link = messageLink(account, dialogId, m.id);
        if (link != null) {
            o.put("link", link);
        }
        o.put("date_utc", utc(m.date));
        o.put("date_unix", m.date);
        if (m.edit_date > 0) {
            o.put("edit_date_utc", utc(m.edit_date));
        }
        long senderId = m.from_id != null ? MessageObject.getPeerId(m.from_id) : dialogId;
        o.put("sender_id", senderId);
        o.put("sender", peerName(account, senderId));
        o.put("text", m.message == null ? "" : m.message);
        o.put("text_sha256", sha256(m.message));
        o.put("views", m.views);
        o.put("forwards", m.forwards);
        if (m.fwd_from != null) {
            JSONObject f = new JSONObject();
            if (m.fwd_from.from_id != null) {
                long origin = MessageObject.getPeerId(m.fwd_from.from_id);
                f.put("from_id", origin);
                f.put("from", peerName(account, origin));
                if (m.fwd_from.channel_post != 0) {
                    f.put("channel_post", m.fwd_from.channel_post);
                    String ol = messageLink(account, origin, m.fwd_from.channel_post);
                    if (ol != null) {
                        f.put("link", ol);
                    }
                }
            }
            if (!TextUtils.isEmpty(m.fwd_from.from_name)) {
                f.put("from_name", m.fwd_from.from_name);
            }
            f.put("date_utc", utc(m.fwd_from.date));
            o.put("forwarded_from", f);
        }
        JSONArray arr = new JSONArray();
        for (Indicator i : indicatorsOf(m)) {
            JSONObject x = new JSONObject();
            x.put("type", i.type);
            x.put("value", i.value);
            arr.put(x);
        }
        o.put("indicators", arr);
        o.put("report", report);
        return o;
    }

    // ---------------------------------------------------------------------
    // UI entry points (called from ChatActivity)
    // ---------------------------------------------------------------------

    public static void showMessageReport(Activity activity, int account, MessageObject mo) {
        if (activity == null || mo == null || mo.messageOwner == null) {
            return;
        }
        final String report = buildMessageReport(account, mo);
        AlertDialog.Builder b = new AlertDialog.Builder(activity);
        b.setTitle(LocaleController.getString(R.string.OsintMessageTitle));
        b.setMessage(report);
        b.setPositiveButton(LocaleController.getString(R.string.OsintCopy), (d, w) -> {
            AndroidUtilities.addToClipboard(report);
            toast(activity, LocaleController.getString(R.string.OsintCopied));
        });
        b.setNeutralButton(LocaleController.getString(R.string.OsintSaveEvidence), (d, w) -> saveEvidence(activity, account, mo, report));
        b.setNegativeButton(LocaleController.getString(R.string.Close), null);
        b.show();
    }

    public static void saveEvidence(Activity activity, int account, MessageObject mo, String report) {
        try {
            JSONObject json = buildMessageJson(account, mo, report);
            String body = json.toString(2);
            String hash = sha256(body);
            String base = "evidence_" + Math.abs(mo.getDialogId()) + "_" + mo.getId() + "_" + fileStamp();
            saveToDownloads(activity, base + ".json", "application/json", body.getBytes(StandardCharsets.UTF_8));
            String txt = report + "\nEvidence file: " + base + ".json\nEvidence file SHA-256: " + hash + "\n";
            saveToDownloads(activity, base + ".txt", "text/plain", txt.getBytes(StandardCharsets.UTF_8));
            toast(activity, LocaleController.formatString(R.string.OsintSaved, "Download/" + DOWNLOAD_SUBDIR + "/" + base));
        } catch (Exception e) {
            FileLog.e(e);
            toast(activity, LocaleController.getString(R.string.OsintSaveError) + ": " + e.getMessage());
        }
    }

    /** Scans the messages currently loaded in a chat and exports indicators to CSV. */
    public static void exportChatIndicators(Activity activity, int account, long dialogId, List<MessageObject> messages) {
        if (activity == null || messages == null) {
            return;
        }
        Map<String, int[]> counts = new LinkedHashMap<>();
        Map<String, MessageObject> first = new LinkedHashMap<>();
        int scanned = 0;
        for (MessageObject mo : messages) {
            if (mo == null || mo.messageOwner == null || mo.getId() == 0) {
                continue;
            }
            scanned++;
            for (Indicator i : indicatorsOf(mo.messageOwner)) {
                String key = i.type + "\u0000" + i.value;
                int[] c = counts.get(key);
                if (c == null) {
                    counts.put(key, new int[]{1});
                    first.put(key, mo);
                } else {
                    c[0]++;
                    MessageObject prev = first.get(key);
                    if (prev != null && mo.messageOwner.date < prev.messageOwner.date) {
                        first.put(key, mo);
                    }
                }
            }
        }
        if (counts.isEmpty()) {
            toast(activity, LocaleController.formatString(R.string.OsintNoIndicators, scanned));
            return;
        }
        StringBuilder csv = new StringBuilder("type,value,count,first_message_id,first_date_utc,first_message_link\n");
        for (Map.Entry<String, int[]> e : counts.entrySet()) {
            String[] kv = e.getKey().split("\u0000", 2);
            MessageObject mo = first.get(e.getKey());
            String link = mo == null ? null : messageLink(account, dialogId, mo.getId());
            csv.append(csvField(kv[0])).append(',')
                    .append(csvField(kv[1])).append(',')
                    .append(e.getValue()[0]).append(',')
                    .append(mo == null ? "" : String.valueOf(mo.getId())).append(',')
                    .append(mo == null ? "" : csvField(utc(mo.messageOwner.date))).append(',')
                    .append(link == null ? "" : csvField(link)).append('\n');
        }
        String name = "indicators_" + Math.abs(dialogId) + "_" + fileStamp() + ".csv";
        try {
            // UTF-8 BOM so Excel opens Cyrillic correctly.
            byte[] bom = new byte[]{(byte) 0xEF, (byte) 0xBB, (byte) 0xBF};
            byte[] data = csv.toString().getBytes(StandardCharsets.UTF_8);
            byte[] all = new byte[bom.length + data.length];
            System.arraycopy(bom, 0, all, 0, bom.length);
            System.arraycopy(data, 0, all, bom.length, data.length);
            saveToDownloads(activity, name, "text/csv", all);
            AlertDialog.Builder b = new AlertDialog.Builder(activity);
            b.setTitle(LocaleController.getString(R.string.OsintIndicatorsTitle));
            b.setMessage(LocaleController.formatString(R.string.OsintIndicatorsResult, scanned, counts.size(), "Download/" + DOWNLOAD_SUBDIR + "/" + name));
            b.setPositiveButton(LocaleController.getString(R.string.OK), null);
            b.show();
        } catch (Exception ex) {
            FileLog.e(ex);
            toast(activity, LocaleController.getString(R.string.OsintSaveError) + ": " + ex.getMessage());
        }
    }

    private static String csvField(String v) {
        if (v == null) {
            return "";
        }
        if (v.indexOf(',') >= 0 || v.indexOf('"') >= 0 || v.indexOf('\n') >= 0) {
            return '"' + v.replace("\"", "\"\"") + '"';
        }
        return v;
    }

    private static void toast(Context ctx, String text) {
        Toast.makeText(ctx, text, Toast.LENGTH_LONG).show();
    }

    /** Saves a file into Download/OsintGram (MediaStore on Android 10+). */
    public static void saveToDownloads(Context ctx, String name, String mime, byte[] data) throws IOException {
        if (Build.VERSION.SDK_INT >= 29) {
            ContentValues v = new ContentValues();
            v.put(MediaStore.MediaColumns.DISPLAY_NAME, name);
            v.put(MediaStore.MediaColumns.MIME_TYPE, mime);
            v.put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS + "/" + DOWNLOAD_SUBDIR);
            Uri uri = ctx.getContentResolver().insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, v);
            if (uri == null) {
                throw new IOException("MediaStore insert failed");
            }
            try (OutputStream os = ctx.getContentResolver().openOutputStream(uri)) {
                if (os == null) {
                    throw new IOException("Cannot open output stream");
                }
                os.write(data);
            }
        } else {
            File dir = new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), DOWNLOAD_SUBDIR);
            if (!dir.exists() && !dir.mkdirs()) {
                throw new IOException("Cannot create " + dir);
            }
            try (FileOutputStream fos = new FileOutputStream(new File(dir, name))) {
                fos.write(data);
            }
        }
    }
}
