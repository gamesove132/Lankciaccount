package com.lankciworld.account;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer;
import org.bukkit.Bukkit;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.command.PluginCommand;
import org.bukkit.command.TabCompleter;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.event.player.PlayerQuitEvent;
import org.bukkit.plugin.Plugin;
import org.bukkit.plugin.java.JavaPlugin;
import org.bukkit.scheduler.BukkitRunnable;
import org.bukkit.scheduler.BukkitTask;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * LankciAccount: зв'язок сервера з сайтом LankciWorld (Supabase).
 *  - /link accept | deny: прив'язка ніка до акаунта сайту;
 *  - вхід з нового IP лише після підтвердження на сайті (за згодою власника акаунта);
 *  - блокування акаунта й «вигнати мене» з сайту;
 *  - історія входів з містом (за згодою).
 * Усі секрети лежать у config.yml на сервері, у цьому коді їх немає.
 */
public final class LankciAccountPlugin extends JavaPlugin implements Listener, CommandExecutor, TabCompleter {

    /* ───────── стан ───────── */
    private volatile boolean ready = false;
    private volatile boolean failOpen = true;
    private volatile Supa supa;
    private volatile Geo geo;
    private volatile byte[] hashKey;
    private final AuthMe authMe = new AuthMe(this);

    /** нікі (малими літерами) гравців, які зараз онлайн: список для опитування сайту */
    private final Set<String> online = ConcurrentHashMap.newKeySet();
    /** нік -> дані про вхід, який уже пройшов перевірку IP (чекаємо, поки гравець ввійде через AuthMe) */
    private final Map<String, Pending> allowed = new ConcurrentHashMap<>();
    /** нік -> активні запити прив'язки (оновлюється при кожному опитуванні) */
    private volatile Map<String, List<LinkReq>> activeLinks = Map.of();
    private final Set<String> notified = ConcurrentHashMap.newKeySet();
    private final Map<String, Long> warnAt = new ConcurrentHashMap<>();
    private final AtomicBoolean polling = new AtomicBoolean(false);
    private BukkitTask pollTask;
    private BukkitTask cleanTask;

    private record Pending(String ipHash, String ip, long at) {}
    private record LinkReq(String id, String mcNick, String fromNick) {}
    private record Kick(String mcNick, String reason) {}

    /* ───────── запуск / зупинка ───────── */
    @Override
    public void onEnable() {
        saveDefaultConfig();
        getServer().getPluginManager().registerEvents(this, this);
        for (String name : new String[] {"link", "lwaccount"}) {
            PluginCommand pc = getCommand(name);
            if (pc != null) {
                pc.setExecutor(this);
                pc.setTabCompleter(this);
            }
        }
        for (Player p : Bukkit.getOnlinePlayers()) {
            online.add(lower(p.getName()));
        }
        start();
    }

    @Override
    public void onDisable() {
        stopTasks();
    }

    private void stopTasks() {
        if (pollTask != null) { pollTask.cancel(); pollTask = null; }
        if (cleanTask != null) { cleanTask.cancel(); cleanTask = null; }
    }

    private void start() {
        stopTasks();
        loadConfig();
        if (!ready) {
            return;
        }
        int sec = Math.max(2, getConfig().getInt("poll-interval-seconds", 5));
        pollTask = Bukkit.getScheduler().runTaskTimerAsynchronously(this, this::pollSafe, 40L, sec * 20L);
        cleanTask = Bukkit.getScheduler().runTaskTimerAsynchronously(this, this::cleanupSafe, 20L * 60L, 20L * 3600L);
        getLogger().info("Готово. Опитування сайту кожні " + sec + " с. fail-open=" + failOpen
                + ". AuthMe: " + (authMe.available() ? "знайдено" : "НЕ знайдено (прив'язка з гри не працюватиме)"));
    }

    private void loadConfig() {
        reloadConfig();
        FileConfiguration c = getConfig();
        String url = c.getString("supabase-url", "").trim();
        String key = c.getString("supabase-key", "").trim();
        String secret = c.getString("plugin-secret", "").trim();
        String hs = c.getString("ip-hash-secret", "").trim();
        failOpen = c.getBoolean("fail-open", true);

        List<String> problems = new ArrayList<>();
        if (!url.startsWith("https://")) problems.add("supabase-url (має починатися з https://)");
        if (key.isEmpty()) problems.add("supabase-key");
        if (secret.length() < 32 || secret.startsWith("ВСТАВ")) problems.add("plugin-secret (мінімум 32 символи)");
        if (hs.length() < 16 || hs.startsWith("ВСТАВ")) problems.add("ip-hash-secret (мінімум 16 символів)");
        if (!problems.isEmpty()) {
            ready = false;
            getLogger().warning("Плагін НЕ налаштований. Заповни у config.yml: " + String.join(", ", problems)
                    + ". Потім виконай /lwaccount reload.");
            return;
        }
        int timeout = Math.max(1000, c.getInt("http-timeout-ms", 3500));
        supa = new Supa(url, key, secret, timeout);
        geo = new Geo(c.getStringList("geo-providers"), Math.max(1, c.getInt("geo-cache-hours", 24)));
        hashKey = hs.getBytes(StandardCharsets.UTF_8);
        ready = true;
    }

    /* ───────── допоміжне ───────── */
    private static String lower(String s) {
        return s == null ? "" : s.toLowerCase(Locale.ROOT);
    }

    private Component c(String key, String... kv) {
        String t = getConfig().getString("messages." + key, key);
        for (int i = 0; i + 1 < kv.length; i += 2) {
            t = t.replace("{" + kv[i] + "}", kv[i + 1] == null ? "" : kv[i + 1]);
        }
        return LegacyComponentSerializer.legacyAmpersand().deserialize(t);
    }

    private void warnThrottled(String key, String msg) {
        long now = System.currentTimeMillis();
        Long last = warnAt.get(key);
        if (last == null || now - last > 60_000L) {
            warnAt.put(key, now);
            getLogger().warning(msg);
        }
    }

    private String hashIp(InetAddress a) {
        if (a == null || hashKey == null) return null;
        String s = a.getHostAddress();
        int i = s.indexOf('%');
        if (i > 0) s = s.substring(0, i);
        try {
            Mac m = Mac.getInstance("HmacSHA256");
            m.init(new SecretKeySpec(hashKey, "HmacSHA256"));
            byte[] d = m.doFinal(s.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(d.length * 2);
            for (byte b : d) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String ipString(InetAddress a) {
        if (a == null) return null;
        String s = a.getHostAddress();
        int i = s.indexOf('%');
        return i > 0 ? s.substring(0, i) : s;
    }

    /* ───────── події ───────── */

    /** Перевірка ДО входу: заблокований акаунт або новий IP. */
    @EventHandler(priority = EventPriority.HIGH)
    public void onPreLogin(AsyncPlayerPreLoginEvent e) {
        if (!ready || e.getLoginResult() != AsyncPlayerPreLoginEvent.Result.ALLOWED) return;
        final String name = e.getName();
        final InetAddress addr = e.getAddress();
        try {
            String ipHash = hashIp(addr);
            JsonObject p = new JsonObject();
            p.addProperty("p_mc_nick", name);
            p.addProperty("p_ip_hash", ipHash);
            JsonObject r = supa.rpc("plugin_login_check", p).getAsJsonObject();
            String action = J.str(r, "action");
            boolean prot = J.bool(r, "protection");

            if ("allow".equals(action)) {
                if (prot) {
                    allowed.put(lower(name), new Pending(ipHash, ipString(addr), System.currentTimeMillis()));
                } else {
                    allowed.remove(lower(name));
                }
                return;
            }

            String msgKey = "deny-new-ip";
            if ("deny_locked".equals(action)) msgKey = "deny-locked";
            else if ("deny_rate".equals(action)) msgKey = "deny-rate";
            e.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, c(msgKey));

            // місто дописуємо окремо, щоб гравець одразу побачив відмову
            final String apId = J.str(r, "approval_id");
            final Long evId = J.lng(r, "event_id");
            if (prot && (apId != null || evId != null)) {
                final String ip = ipString(addr);
                Bukkit.getScheduler().runTaskAsynchronously(this, () -> {
                    try {
                        Geo.Place pl = geo.lookup(ip);
                        JsonObject q = new JsonObject();
                        q.add("p_approval_id", apId == null ? JsonNull.INSTANCE : new com.google.gson.JsonPrimitive(apId));
                        q.add("p_event_id", evId == null ? JsonNull.INSTANCE : new com.google.gson.JsonPrimitive(evId));
                        q.addProperty("p_city", pl.city());
                        q.addProperty("p_region", pl.region());
                        q.addProperty("p_country", pl.country());
                        supa.rpc("plugin_set_geo", q);
                    } catch (Exception ex) {
                        warnThrottled("geo-set", "Не вдалося записати місто: " + ex.getMessage());
                    }
                });
            }
        } catch (Exception ex) {
            warnThrottled("prelogin", "Перевірка входу не вдалася для " + name + ": " + ex.getMessage()
                    + (failOpen ? " (пускаємо, fail-open)" : " (НЕ пускаємо, fail-open=false)"));
            if (!failOpen) {
                e.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, c("deny-error"));
            }
        }
    }

    @EventHandler
    public void onJoin(PlayerJoinEvent e) {
        Player p = e.getPlayer();
        online.add(lower(p.getName()));
        if (ready) watchAuth(p);
    }

    @EventHandler
    public void onQuit(PlayerQuitEvent e) {
        String l = lower(e.getPlayer().getName());
        online.remove(l);
        allowed.remove(l);
    }

    /** Чекаємо, поки гравець пройде AuthMe (до 3 хвилин), і лише тоді фіксуємо вхід. */
    private void watchAuth(Player p) {
        if (!authMe.available()) {
            warnThrottled("authme-missing", "AuthMe не знайдено: входи не записуються, /link не працює.");
            return;
        }
        new BukkitRunnable() {
            int seconds = 0;
            @Override
            public void run() {
                if (!p.isOnline()) { cancel(); return; }
                if (authMe.isAuthenticated(p)) { cancel(); onAuthenticated(p); return; }
                seconds++;
                if (seconds > 180) cancel();
            }
        }.runTaskTimer(this, 20L, 20L);
    }

    /** Головний потік: гравець ввійшов через AuthMe. */
    private void onAuthenticated(Player p) {
        Bukkit.getScheduler().runTaskAsynchronously(this, this::pollSafe);
        final Pending pd = allowed.remove(lower(p.getName()));
        if (pd == null || System.currentTimeMillis() - pd.at() > 15 * 60_000L) return;
        final String nick = p.getName();
        Bukkit.getScheduler().runTaskAsynchronously(this, () -> {
            try {
                Geo.Place pl = geo.lookup(pd.ip());
                JsonObject q = new JsonObject();
                q.addProperty("p_mc_nick", nick);
                q.addProperty("p_ip_hash", pd.ipHash());
                q.addProperty("p_city", pl.city());
                q.addProperty("p_region", pl.region());
                q.addProperty("p_country", pl.country());
                supa.rpc("plugin_record_login", q);
            } catch (Exception ex) {
                warnThrottled("record", "Не вдалося записати вхід " + nick + ": " + ex.getMessage());
            }
        });
    }

    /* ───────── опитування сайту (асинхронно) ───────── */
    private void pollSafe() {
        if (!ready || online.isEmpty()) return;
        if (!polling.compareAndSet(false, true)) return;
        try {
            JsonArray arr = new JsonArray();
            for (String n : online) arr.add(n);
            JsonObject p = new JsonObject();
            p.add("p_online", arr);
            JsonObject r = supa.rpc("plugin_pull", p).getAsJsonObject();

            List<LinkReq> links = new ArrayList<>();
            for (JsonElement el : J.arr(r, "links")) {
                JsonObject o = el.getAsJsonObject();
                links.add(new LinkReq(J.str(o, "id"), J.str(o, "mc_nick"), J.str(o, "from_nick")));
            }
            List<Kick> kicks = new ArrayList<>();
            for (JsonElement el : J.arr(r, "kicks")) {
                JsonObject o = el.getAsJsonObject();
                kicks.add(new Kick(J.str(o, "mc_nick"), J.str(o, "reason")));
            }
            Bukkit.getScheduler().runTask(this, () -> applyPull(links, kicks));
        } catch (Exception ex) {
            warnThrottled("poll", "Не вдалося опитати Supabase: " + ex.getMessage());
        } finally {
            polling.set(false);
        }
    }

    /** Головний потік: показуємо запити й виконуємо кіки. */
    private void applyPull(List<LinkReq> links, List<Kick> kicks) {
        Map<String, List<LinkReq>> next = new HashMap<>();
        Set<String> ids = new HashSet<>();
        for (LinkReq r : links) {
            next.computeIfAbsent(lower(r.mcNick()), k -> new ArrayList<>()).add(r);
            ids.add(r.id());
        }
        activeLinks = next;
        notified.retainAll(ids);

        for (LinkReq r : links) {
            Player pl = Bukkit.getPlayerExact(r.mcNick());
            if (pl == null || !authMe.isAuthenticated(pl)) continue;
            if (!notified.add(r.id())) continue;
            pl.sendMessage(c("link-request", "site", r.fromNick()));
            pl.sendMessage(c("link-request-accept", "site", r.fromNick()));
            pl.sendMessage(c("link-request-deny", "site", r.fromNick()));
        }

        for (Kick k : kicks) {
            Player pl = Bukkit.getPlayerExact(k.mcNick());
            if (pl != null) {
                pl.kick(c("locked".equals(k.reason()) ? "kick-locked" : "kick-self"));
            }
        }
    }

    private void cleanupSafe() {
        if (!ready) return;
        try {
            supa.rpc("plugin_cleanup", new JsonObject());
        } catch (Exception ex) {
            warnThrottled("cleanup", "Прибирання старих даних не вдалося: " + ex.getMessage());
        }
    }

    /* ───────── команди ───────── */
    @Override
    public boolean onCommand(CommandSender sender, Command cmd, String label, String[] args) {
        String n = cmd.getName().toLowerCase(Locale.ROOT);
        if (n.equals("link")) return doLink(sender, args);
        if (n.equals("lwaccount")) return doAdmin(sender, args);
        return false;
    }

    @Override
    public List<String> onTabComplete(CommandSender sender, Command cmd, String alias, String[] args) {
        List<String> out = new ArrayList<>();
        String n = cmd.getName().toLowerCase(Locale.ROOT);
        if (args.length == 1) {
            String[] opts = n.equals("link") ? new String[] {"accept", "deny"} : new String[] {"status", "reload", "debug"};
            for (String o : opts) if (o.startsWith(args[0].toLowerCase(Locale.ROOT))) out.add(o);
        } else if (args.length == 2 && n.equals("link") && sender instanceof Player p) {
            for (LinkReq r : activeLinks.getOrDefault(lower(p.getName()), List.of())) {
                if (r.fromNick() != null && lower(r.fromNick()).startsWith(args[1].toLowerCase(Locale.ROOT))) out.add(r.fromNick());
            }
        }
        return out;
    }

    private boolean doLink(CommandSender s, String[] a) {
        if (!(s instanceof Player p)) {
            s.sendMessage(c("only-player"));
            return true;
        }
        if (!ready) { p.sendMessage(c("link-error")); return true; }
        if (!authMe.available()) { p.sendMessage(c("link-unavailable")); return true; }
        if (!authMe.isAuthenticated(p)) { p.sendMessage(c("need-login")); return true; }
        if (a.length < 1 || !(a[0].equalsIgnoreCase("accept") || a[0].equalsIgnoreCase("deny"))) {
            p.sendMessage(c("link-usage"));
            return true;
        }
        final boolean accept = a[0].equalsIgnoreCase("accept");
        List<LinkReq> list = activeLinks.getOrDefault(lower(p.getName()), List.of());
        LinkReq pick = null;
        if (a.length >= 2) {
            for (LinkReq r : list) if (r.fromNick() != null && r.fromNick().equalsIgnoreCase(a[1])) pick = r;
        } else if (list.size() == 1) {
            pick = list.get(0);
        }
        if (pick == null) {
            if (list.isEmpty()) {
                p.sendMessage(c("link-none"));
            } else {
                StringBuilder names = new StringBuilder();
                for (LinkReq r : list) { if (names.length() > 0) names.append(", "); names.append(r.fromNick()); }
                p.sendMessage(c("link-multi", "sites", names.toString()));
            }
            return true;
        }
        final LinkReq req = pick;
        final String nick = p.getName();
        final String ipHash = (p.getAddress() != null) ? hashIp(p.getAddress().getAddress()) : null;
        Bukkit.getScheduler().runTaskAsynchronously(this, () -> {
            String res;
            try {
                JsonObject q = new JsonObject();
                q.addProperty("p_request_id", req.id());
                q.addProperty("p_mc_nick", nick);
                q.addProperty("p_accept", accept);
                q.addProperty("p_ip_hash", ipHash);
                res = supa.rpc("plugin_link_answer", q).getAsString();
            } catch (Exception ex) {
                warnThrottled("link", "Помилка /link для " + nick + ": " + ex.getMessage());
                res = "error";
            }
            final String result = res;
            Bukkit.getScheduler().runTask(this, () -> {
                Player pl = Bukkit.getPlayerExact(nick);
                if (pl == null) return;
                String key = switch (result) {
                    case "ok" -> "link-ok";
                    case "denied" -> "link-denied";
                    case "expired", "not_found", "not_pending" -> "link-gone";
                    case "mc_nick_taken", "already_linked" -> "link-taken";
                    default -> "link-error";
                };
                pl.sendMessage(c(key, "site", req.fromNick()));
                pollSafeAsync();
            });
        });
        return true;
    }

    private void pollSafeAsync() {
        Bukkit.getScheduler().runTaskAsynchronously(this, this::pollSafe);
    }

    private boolean doAdmin(CommandSender s, String[] a) {
        if (!s.hasPermission("lankciaccount.admin")) {
            s.sendMessage(c("no-permission"));
            return true;
        }
        String sub = a.length > 0 ? a[0].toLowerCase(Locale.ROOT) : "status";
        switch (sub) {
            case "reload" -> {
                start();
                s.sendMessage("§aLankciAccount: конфіг перезавантажено. Налаштований: " + (ready ? "так" : "ні (див. консоль)"));
            }
            case "debug" -> debug(s);
            default -> status(s);
        }
        return true;
    }

    private void status(CommandSender s) {
        s.sendMessage("§6LankciAccount: §fналаштований: " + (ready ? "§aтак" : "§cні (див. консоль)"));
        s.sendMessage("§6AuthMe: §f" + (authMe.available() ? "§aзнайдено" : "§cне знайдено"));
        s.sendMessage("§6fail-open: §f" + failOpen);
        if (!ready) return;
        Bukkit.getScheduler().runTaskAsynchronously(this, () -> {
            String res;
            try {
                JsonObject q = new JsonObject();
                q.add("p_online", new JsonArray());
                supa.rpc("plugin_pull", q);
                res = "§aOK (секрет і ключ прийняті)";
            } catch (Exception ex) {
                res = "§cпомилка: " + ex.getMessage();
            }
            final String out = res;
            Bukkit.getScheduler().runTask(this, () -> s.sendMessage("§6Supabase: §f" + out));
        });
    }

    /** Показує, які IP бачить плагін (щоб зрозуміти, чи хостинг не підміняє їх проксі). */
    private void debug(CommandSender s) {
        Map<String, Integer> perIp = new HashMap<>();
        List<Player> players = new ArrayList<>(Bukkit.getOnlinePlayers());
        for (Player p : players) {
            if (p.getAddress() == null) continue;
            perIp.merge(ipString(p.getAddress().getAddress()), 1, Integer::sum);
        }
        s.sendMessage("§6Гравці онлайн та IP, які бачить плагін (частково приховані):");
        if (players.isEmpty()) s.sendMessage("§7нікого немає онлайн");
        for (Player p : players) {
            if (p.getAddress() == null) continue;
            String ip = ipString(p.getAddress().getAddress());
            boolean priv = Geo.isPrivate(ip);
            s.sendMessage("§f" + p.getName() + " §7→ §f" + mask(ip)
                    + (priv ? " §c(локальна адреса!)" : "")
                    + " §7(гравців з цим IP: " + perIp.get(ip) + ")");
        }
        s.sendMessage("§7Якщо ВСІ гравці мають однаковий IP або локальну адресу, сервер стоїть за проксі/тунелем:"
                + " тоді захист за IP працювати не буде. Не вмикай його, поки не з'ясуєш це.");
    }

    private static String mask(String ip) {
        if (ip == null) return "?";
        if (ip.contains(":")) {
            String[] p = ip.split(":");
            return p[0] + ":" + (p.length > 1 ? p[1] : "") + ":…";
        }
        String[] p = ip.split("\\.");
        return p.length == 4 ? p[0] + "." + p[1] + ".*.*" : "?";
    }

    /* ═════════ JSON-помічник ═════════ */
    static final class J {
        private J() {}
        static String str(JsonObject o, String k) {
            JsonElement e = o.get(k);
            return (e == null || e.isJsonNull()) ? null : e.getAsString();
        }
        static boolean bool(JsonObject o, String k) {
            JsonElement e = o.get(k);
            return e != null && !e.isJsonNull() && e.getAsBoolean();
        }
        static Long lng(JsonObject o, String k) {
            JsonElement e = o.get(k);
            return (e == null || e.isJsonNull()) ? null : e.getAsLong();
        }
        static JsonArray arr(JsonObject o, String k) {
            JsonElement e = o.get(k);
            return (e != null && e.isJsonArray()) ? e.getAsJsonArray() : new JsonArray();
        }
    }

    /* ═════════ Клієнт Supabase (RPC через REST) ═════════ */
    static final class Supa {
        static final class SupaException extends Exception {
            private static final long serialVersionUID = 1L;
            SupaException(String m) { super(m); }
        }

        private static final Gson GSON = new Gson();
        private final HttpClient http;
        private final String base;
        private final String key;
        private final String secret;
        private final Duration timeout;

        Supa(String url, String key, String secret, int timeoutMs) {
            this.base = url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
            this.key = key;
            this.secret = secret;
            this.timeout = Duration.ofMillis(timeoutMs);
            this.http = HttpClient.newBuilder().connectTimeout(timeout).build();
        }

        /** Викликає SQL-функцію public.<fn>. Секрет плагіна додається автоматично. */
        JsonElement rpc(String fn, JsonObject params) throws SupaException {
            params.addProperty("p_secret", secret);
            try {
                HttpRequest req = HttpRequest.newBuilder(URI.create(base + "/rest/v1/rpc/" + fn))
                        .timeout(timeout)
                        .header("apikey", key)
                        .header("Content-Type", "application/json")
                        .header("Accept", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(GSON.toJson(params), StandardCharsets.UTF_8))
                        .build();
                HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
                String body = resp.body() == null ? "" : resp.body();
                if (resp.statusCode() / 100 != 2) {
                    String msg = body;
                    try {
                        JsonObject o = JsonParser.parseString(body).getAsJsonObject();
                        if (o.has("message")) msg = o.get("message").getAsString();
                    } catch (Exception ignored) { /* залишаємо сирий текст */ }
                    if (msg.length() > 200) msg = msg.substring(0, 200);
                    throw new SupaException("HTTP " + resp.statusCode() + ": " + msg);
                }
                if (body.isBlank()) return JsonNull.INSTANCE;
                return JsonParser.parseString(body);
            } catch (SupaException e) {
                throw e;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new SupaException("перервано");
            } catch (Exception e) {
                throw new SupaException(e.getClass().getSimpleName() + ": " + e.getMessage());
            }
        }
    }

    /* ═════════ Геолокація за IP (лише за згодою, лише з сервера) ═════════ */
    static final class Geo {
        record Place(String city, String region, String country) {
            static final Place EMPTY = new Place(null, null, null);
            boolean empty() { return city == null && region == null && country == null; }
        }

        private record Cached(Place place, long at) {}

        private static final long NEG_MS = 5 * 60_000L;
        private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(4)).build();
        private final List<String> providers;
        private final long ttlMs;
        private final Map<String, Cached> cache = new ConcurrentHashMap<>();

        Geo(List<String> providers, int cacheHours) {
            this.providers = (providers == null || providers.isEmpty())
                    ? List.of("ipwhois", "ipapi", "freeipapi") : providers;
            this.ttlMs = cacheHours * 3_600_000L;
        }

        static boolean isPrivate(String ip) {
            if (ip == null) return true;
            try {
                InetAddress a = InetAddress.getByName(ip); // це числова адреса, DNS не використовується
                return a.isAnyLocalAddress() || a.isLoopbackAddress() || a.isSiteLocalAddress()
                        || a.isLinkLocalAddress() || a.isMulticastAddress();
            } catch (Exception e) {
                return true;
            }
        }

        Place lookup(String ip) {
            if (ip == null || isPrivate(ip)) return Place.EMPTY;
            long now = System.currentTimeMillis();
            Cached cd = cache.get(ip);
            if (cd != null && now - cd.at() < (cd.place().empty() ? NEG_MS : ttlMs)) return cd.place();
            if (cache.size() > 2000) cache.clear();
            for (String prov : providers) {
                try {
                    Place p = query(prov.toLowerCase(Locale.ROOT), ip);
                    if (p != null && !p.empty()) {
                        cache.put(ip, new Cached(p, now));
                        return p;
                    }
                } catch (Exception ignored) { /* пробуємо наступний сервіс */ }
            }
            cache.put(ip, new Cached(Place.EMPTY, now));
            return Place.EMPTY;
        }

        private Place query(String prov, String ip) throws Exception {
            switch (prov) {
                case "ipwhois": {
                    JsonObject o = get("https://ipwho.is/" + ip);
                    if (o == null) return null;
                    if (o.has("success") && !o.get("success").getAsBoolean()) return null;
                    return new Place(J.str(o, "city"), J.str(o, "region"), J.str(o, "country"));
                }
                case "ipapi": {
                    JsonObject o = get("https://ipapi.co/" + ip + "/json/");
                    if (o == null || o.has("error")) return null;
                    return new Place(J.str(o, "city"), J.str(o, "region"), J.str(o, "country_name"));
                }
                case "freeipapi": {
                    JsonObject o = get("https://free.freeipapi.com/api/json/" + ip);
                    if (o == null) return null;
                    return new Place(J.str(o, "cityName"), J.str(o, "regionName"), J.str(o, "countryName"));
                }
                default:
                    return null;
            }
        }

        private JsonObject get(String url) throws Exception {
            HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                    .timeout(Duration.ofSeconds(4))
                    .header("User-Agent", "LankciAccount/1.0")
                    .header("Accept", "application/json")
                    .GET().build();
            HttpResponse<String> r = http.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (r.statusCode() != 200) return null;
            JsonElement el = JsonParser.parseString(r.body());
            return el.isJsonObject() ? el.getAsJsonObject() : null;
        }
    }

    /* ═════════ Зв'язок з AuthMe (через reflection, без залежності при збірці) ═════════ */
    static final class AuthMe {
        private final LankciAccountPlugin pl;
        private Object api;
        private Method isAuth;
        private boolean warned;

        AuthMe(LankciAccountPlugin pl) { this.pl = pl; }

        synchronized boolean available() {
            init();
            return api != null && isAuth != null;
        }

        private void init() {
            if (api != null && isAuth != null) return;
            Plugin am = Bukkit.getPluginManager().getPlugin("AuthMe");
            if (am == null || !am.isEnabled()) return;
            try {
                Class<?> cls = Class.forName("fr.xephi.authme.api.v3.AuthMeApi", true, am.getClass().getClassLoader());
                api = cls.getMethod("getInstance").invoke(null);
                isAuth = cls.getMethod("isAuthenticated", Player.class);
            } catch (Throwable t) {
                api = null;
                isAuth = null;
                if (!warned) {
                    warned = true;
                    pl.getLogger().warning("Не вдалося підключитися до API AuthMe (" + t + "). "
                            + "Можливо, змінилась версія AuthMe: напиши про це розробнику плагіна.");
                }
            }
        }

        boolean isAuthenticated(Player p) {
            if (!available()) return false;
            try {
                Object r = isAuth.invoke(api, p);
                return r instanceof Boolean b && b;
            } catch (Throwable t) {
                return false;
            }
        }
    }
}
