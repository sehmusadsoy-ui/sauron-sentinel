"use strict";

(() => {
  const node = (id) => document.getElementById(id);
  const token = document.querySelector('meta[name="sentinel-token"]')?.content || "";
  const severityNames = { critical: "Kritik", high: "Yüksek", medium: "Orta", low: "Düşük" };
  const alertNames = {
    "auth-failure-burst": "Art arda başarısız oturum açma",
    "windows-service-installed": "Yeni Windows hizmeti kuruldu",
    "windows-log-cleared": "Windows olay günlüğü temizlendi",
    "windows-defender-threat": "Microsoft Defender tehdit tespit etti",
    "windows-defender-disabled": "Microsoft Defender koruması kapatıldı",
    "windows-account-created": "Yeni Windows hesabı oluşturuldu",
    "windows-group-member-added": "Yerel güvenlik grubuna üye eklendi",
    "windows-unexpected-shutdown": "Windows beklenmedik biçimde kapandı",
  };
  const sourceErrors = {
    permission_denied: "Bu günlüğü okumak için gerekli izin alınamadı.",
    channel_unavailable: "Bu günlük bu bilgisayarda kullanılamıyor.",
    channel_disabled: "Bu Windows günlüğü etkin değil.",
    collection_failed: "Günlük okunamadı. Bir sonraki taramada yeniden denenecek.",
    invalid_event: "Bir kayıt beklenen biçimde okunamadı.",
    timeout: "Windows günlüğü beklenen sürede yanıt vermedi.",
    invalid_response: "Windows günlüklerinin yanıtı okunamadı.",
    not_windows: "Windows olay günlükleri yalnızca Windows üzerinde okunabilir.",
    powershell_unavailable: "Windows günlüklerini okumak için gereken PowerShell bulunamadı.",
  };
  const sourcePurposes = {
    System: "Hizmet kurulumu ve başlangıç değişiklikleri, açılış/kapanış ve günlük temizleme kayıtları.",
    Security: "Oturum açma, yerel hesap/grup değişiklikleri ve günlük temizleme kayıtları.",
    "Microsoft-Windows-Windows Defender/Operational": "Defender tehdit, işlem ve koruma ayarı kayıtları.",
  };
  const sourceNextSteps = {
    permission_denied: "Bu günlüğün okuma izinlerini Olay Görüntüleyicisi’nde kontrol et veya yetkili kullanıcıdan destek al.",
    channel_unavailable: "Bu kanalın bilgisayarındaki Windows sürümünde mevcut olup olmadığını Olay Görüntüleyicisi’nde kontrol et.",
    channel_disabled: "Bu kanalın durumunu Olay Görüntüleyicisi’nde kontrol et. Uygulama Windows günlük ayarlarını değiştirmez.",
    timeout: "Bir sonraki kontrolü bekle veya biraz sonra Şimdi tara düğmesini kullan.",
    not_windows: "Canlı izleme için uygulamayı bir Windows bilgisayarda aç.",
    powershell_unavailable: "Windows PowerShell’in kullanılabilirliğini kontrol et veya sistem yöneticisinden destek al.",
  };
  const kindNames = {
    "auth.failure": "Başarısız oturum açma",
    "auth.success": "Başarılı oturum açma",
    "security.log.cleared": "Güvenlik günlüğü temizlendi",
    "audit.log.cleared": "Denetim günlüğü temizlendi",
    "service.installed": "Yeni hizmet kuruldu",
    "service.install": "Yeni hizmet kuruldu",
    "defender.threat": "Defender tehdit bildirimi",
    "defender.threat.detected": "Defender tehdit bildirimi",
    "defender.detection": "Defender tehdit bildirimi",
    "defender.action": "Defender işlem bildirimi",
    "defender.disabled": "Defender koruması devre dışı bırakıldı",
    "defender.config_changed": "Defender ayarları değişti",
    "service.start_changed": "Hizmet başlangıç türü değişti",
    "log.cleared": "Olay günlüğü temizlendi",
    "system.started": "Sistem başlatıldı",
    "system.stopped": "Sistem kapatıldı",
    "system.unexpected_shutdown": "Beklenmeyen sistem kapanışı",
    "account.created": "Kullanıcı hesabı oluşturuldu",
    "group.member_added": "Gruba üye eklendi",
    "process.created": "İşlem başlatıldı",
    "system.event": "Sistem olayı",
    "windows.event": "Windows olayı",
  };
  const attributeNames = {
    event_id: "Windows olay kimliği", record_id: "Günlük kayıt numarası", channel: "Günlük",
    provider: "Sağlayıcı", user: "Kullanıcı", target_user: "Hedef kullanıcı", domain: "Etki alanı",
    ip: "IP adresi", ip_address: "IP adresi", source_ip: "Kaynak IP", service_name: "Hizmet",
    service_path: "Hizmet yolu", threat_name: "Tehdit adı", process_name: "İşlem",
    logon_type: "Oturum türü", status: "Durum", action: "İşlem", computer: "Bilgisayar",
    service_type: "Hizmet türü", start_type: "Başlangıç türü", old_start_type: "Önceki başlangıç türü", group_name: "Grup",
  };
  const state = { data: null, fetching: false, scanning: false, evidenceRequest: 0, renderedEvents: "", renderedAlerts: "", renderedSources: "" };
  const numberFormat = new Intl.NumberFormat("tr-TR");
  const timeFormat = new Intl.DateTimeFormat("tr-TR", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  const dateFormat = new Intl.DateTimeFormat("tr-TR", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" });
  const fullDateFormat = new Intl.DateTimeFormat("tr-TR", { dateStyle: "medium", timeStyle: "medium" });

  function element(tag, className, text) {
    const result = document.createElement(tag);
    if (className) result.className = className;
    if (text !== undefined && text !== null) result.textContent = String(text);
    return result;
  }

  function formatDate(value, format = fullDateFormat) {
    const date = new Date(value);
    return value && !Number.isNaN(date.getTime()) ? format.format(date) : "—";
  }

  function count(value) {
    return typeof value === "number" && Number.isFinite(value) ? numberFormat.format(value) : "—";
  }

  function sourceName(channel) {
    const name = String(channel || "Bilinmeyen kaynak");
    if (name.includes("Windows Defender")) return "Windows Defender";
    return { Security: "Security · Güvenlik", System: "System · Sistem", Application: "Application · Uygulama" }[name] || name;
  }

  function scalar(value) {
    if (value === null || value === undefined || value === "") return "—";
    if (typeof value === "boolean") return value ? "Evet" : "Hayır";
    return String(value);
  }

  function addDetail(list, label, value, identifier = false) {
    list.append(element("dt", "", label), element("dd", identifier ? "identifier" : "", scalar(value)));
  }

  function notice(id, message) {
    const target = node(id);
    if (target.textContent !== (message || "")) target.textContent = message || "";
    target.hidden = !message;
  }

  async function api(path, options = {}, timeout = 15000) {
    const controller = new AbortController();
    const timer = window.setTimeout(() => controller.abort(), timeout);
    try {
      const response = await fetch(path, { credentials: "same-origin", cache: "no-store", ...options, signal: controller.signal });
      if (!response.ok) {
        let explanation = "";
        try {
          const body = await response.json();
          if (typeof body.error === "string") explanation = body.error;
        } catch { /* Non-JSON failures receive the same useful local message. */ }
        if (response.status === 403) throw new Error("Oturum doğrulanamadı. Sayfayı yenileyip tekrar dene.");
        if (response.status === 409) throw new Error("Bir tarama zaten sürüyor. Birkaç saniye sonra yeniden dene.");
        throw new Error(explanation || `İşlem tamamlanamadı (${response.status}).`);
      }
      return await response.json();
    } finally {
      window.clearTimeout(timer);
    }
  }

  function renderHealth(health, monitor) {
    const status = ["starting", "ready", "partial", "unavailable", "error", "stopped"].includes(health.status) ? health.status : "starting";
    const labels = { starting: "Başlıyor", ready: "Kaynaklar okunabildi", partial: "Kısmi görünürlük", unavailable: "Kaynaklar okunamıyor", error: "Kontrol gerekli", stopped: "İzleme durdu" };
    const available = `${count(health.sources_ok)} / ${count(health.sources_total)} kaynak`;
    const messages = {
      starting: ["İlk kontrol bekleniyor", "Windows günlükleri henüz kontrol edilmedi. Saklanan geçmiş kayıtlar, şu anda veri okunabildiğini göstermez.", "İlk kontrol tamamlanana kadar bekle."],
      ready: ["Windows kaynaklarının son kontrolü tamamlandı", `${available} okunabildi. Bu durum günlük erişimini gösterir; tüm olayların kaydedildiğini veya bilgisayarın güvende olduğunu kanıtlamaz.`, "Olayları ve alarm ayrıntılarını aşağıdan inceleyebilirsin."],
      partial: ["Windows olaylarının bir bölümü görülebiliyor", `${available} okunabildi. ${health.sources_limited > 0 ? `${count(health.sources_limited)} kaynakta kayıt sınırına ulaşıldı; bazı kayıtlar kapsam dışında kalmış olabilir.` : "Diğer kaynaklar okunamadı veya henüz sonuç vermedi."}`, "Kaynak kartlarındaki açıklamaları kontrol et; erişilebilen kaynakların kayıtları izlenmeye devam eder."],
      unavailable: ["Windows günlükleri şu anda okunamıyor", "Son kontrolde hiçbir kaynağın okunabilirliği doğrulanamadı. Kayıt olmaması, olay yaşanmadığı anlamına gelmez.", "Aşağıdaki kaynak açıklamalarından eksik izin veya kapalı kanal durumunu kontrol et."],
      error: ["Son kontrol tamamlanamadı", health.source_results_current ? "Son kontrolde kaynakların okunması sırasında sorun oluştu." : "Kaynak kartları varsa önceki sonuçları gösterir; güncel erişim durumu doğrulanamadı.", "Bir sonraki kontrolü bekle veya Şimdi tara düğmesiyle yeniden dene; sorun sürerse kaynak açıklamalarını kontrol et."],
      stopped: ["İzleme durdu", "Saklanan olaylar ve son kaynak sonuçları gösteriliyor. Yeni Windows kayıtları şu anda kontrol edilmiyor.", "İzlemeyi sürdürmek için uygulamayı yeniden aç."],
    };
    const [title, summary, next] = messages[status];
    node("health-title").textContent = title;
    node("health-summary").textContent = summary;
    node("health-next").textContent = monitor.scanning ? "Yeni kontrol sürüyor; kaynak kartları son tamamlanan kontrolü gösterir." : next;
    node("health-badge").textContent = labels[status];
    node("health-badge").className = `health-badge ${status}`;
  }

  function renderSources(sources, monitor, health) {
    const fragment = document.createDocumentFragment();
    let needsPermission = false;
    for (const source of sources) {
      const channel = String(source.channel || source.name || "");
      const status = ["ok", "unavailable", "error"].includes(source.status) ? source.status : "pending";
      const card = element("article", "source-card");
      const content = element("div", "source-content");
      const titleRow = element("div", "source-title-row");
      const stale = health.source_results_current === false;
      const label = { ok: stale ? "Önceki kontrolde okundu" : "Okunabildi", unavailable: "Okunamadı", error: "Kontrol gerekli", pending: "Bekleniyor" }[status];
      titleRow.append(element("h3", "source-title", sourceName(channel)), element("span", `source-state ${status}`, label));
      content.append(titleRow, element("p", "source-purpose", sourcePurposes[channel] || "Seçili Windows olay kayıtları."));
      content.append(element("p", "source-count", status === "ok" ? `${count(source.event_count)} seçili kayıt · son kontrol` : "Bu kontrolde okuma doğrulanamadı"));
      content.append(element("p", "source-success", source.last_success_at ? `Son başarılı okuma: ${formatDate(source.last_success_at)}` : "Bu açılışta henüz başarılı okuma yok"));
      if (status === "ok" && source.event_count === 0) content.append(element("p", "source-note", "Günlük okunabildi; sorgu aralığında seçili kayıt bulunmadı. Bu, ilgili Windows denetimlerinin açık olduğunu kanıtlamaz."));
      if (source.limit_reached) content.append(element("p", "source-warning", "Kayıt sınırına ulaşıldı; sorgu aralığının tamamı kapsanmayabilir. İlgili günlüğü Olay Görüntüleyicisi’nde kontrol edebilirsin."));
      if (source.error) {
        const details = element("details", "source-error");
        content.append(element("p", "source-warning", sourceErrors[source.error] || "Bu kaynak şu anda okunamıyor."));
        details.append(element("summary", "", "Ne yapabilirim?"), element("p", "", sourceNextSteps[source.error] || "Bir sonraki kontrolü bekle veya biraz sonra Şimdi tara düğmesiyle yeniden dene."));
        content.append(details);
      }
      card.append(element("span", "source-icon", channel.includes("Defender") ? "◇" : "▤"), content);
      fragment.append(card);
      if (channel === "Security" && source.error === "permission_denied") needsPermission = true;
    }
    if (!sources.length) fragment.append(element("p", "source-placeholder", "Henüz bir Windows kaynağı raporlanmadı. İlk tarama sonrasında kaynak durumları burada görünür."));
    const fingerprint = JSON.stringify([sources, health.source_results_current]);
    if (state.renderedSources !== fingerprint) {
      node("source-list").replaceChildren(fragment);
      state.renderedSources = fingerprint;
    }
    node("permission-note").hidden = !needsPermission;
    notice("coverage-note", monitor.late_events > 0 ? `${count(monitor.late_events)} gecikmeli kayıt saklandı; bu kontrolde anlık alarm değerlendirmesine alınmadı. Yeniden açılışta veya kurtarma sırasında saklanan kayıtların yeniden değerlendirilmesi geçmiş zamana ait alarm oluşturabilir.` : "");
    const interval = typeof monitor.interval_seconds === "number" ? ` · ${count(monitor.interval_seconds)} sn aralıkla` : "";
    node("monitor-status").textContent = monitor.scanning ? "Windows günlükleri taranıyor…" : monitor.running ? `Otomatik izleme açık${interval}` : "Otomatik izleme duraklatıldı";
  }

  function titleForEvent(event) {
    return kindNames[event.kind] || event.kind || "Windows olayı";
  }

  function eventItem(event, expanded = false) {
    const attributes = event.attributes || {};
    const item = element("li", "event-item");
    const details = element("details");
    if (expanded) details.open = true;
    const summary = element("summary", "event-summary");
    const attention = /failure|cleared|threat|detection/.test(event.kind || "");
    const dot = element("span", attention ? "event-dot attention" : "event-dot");
    dot.setAttribute("aria-hidden", "true");
    const text = element("div", "event-text");
    const firstLine = element("div", "event-line");
    const time = element("time", "event-time", formatDate(event.timestamp, dateFormat));
    time.dateTime = event.timestamp || "";
    time.title = formatDate(event.timestamp);
    firstLine.append(element("span", "event-title", titleForEvent(event)), time);
    const meta = element("div", "event-meta");
    meta.append(element("span", "", event.device_id || "Cihaz bilinmiyor"));
    const user = attributes.user || attributes.target_user || attributes.service_name || attributes.threat_name;
    if (user) meta.append(element("span", "", user));
    if (attributes.event_id !== undefined) meta.append(element("span", "event-kind", `ID ${attributes.event_id}`));
    if (event.synthetic) meta.append(element("small", "synthetic-badge", "SENTETİK"));
    text.append(firstLine, meta);
    summary.append(dot, text);
    const detail = element("div", "event-detail");
    const grid = element("dl", "details-grid");
    addDetail(grid, "Zaman", formatDate(event.timestamp));
    addDetail(grid, "Olay türü", event.kind);
    addDetail(grid, "Kaynak", event.source);
    addDetail(grid, "Veri", event.synthetic ? "Sentetik örnek" : "Gerçek kayıt");
    for (const [key, value] of Object.entries(attributes)) addDetail(grid, attributeNames[key] || key, value);
    addDetail(grid, "Kayıt kimliği", event.event_id, true);
    detail.append(grid);
    details.append(summary, detail);
    item.append(details);
    return item;
  }

  function searchMatches(value, query) {
    if (!query) return true;
    return JSON.stringify(value).toLocaleLowerCase("tr-TR").includes(query);
  }

  function emptyState(id, title, description, visible) {
    const target = node(id);
    target.hidden = !visible;
    target.querySelector("h3").textContent = title;
    target.querySelector("p").textContent = description;
  }

  function renderEvents() {
    if (!state.data) return;
    const events = Array.isArray(state.data.events) ? state.data.events : [];
    const query = node("search-input").value.trim().toLocaleLowerCase("tr-TR");
    const kind = node("event-kind-filter").value;
    const filtered = events.filter((event) => (!kind || event.kind === kind) && searchMatches([event, titleForEvent(event)], query));
    const fingerprint = JSON.stringify([events.map((event) => event.event_id), query, kind]);
    if (state.renderedEvents === fingerprint) return;
    state.renderedEvents = fingerprint;
    const openIds = new Set([...node("event-list").querySelectorAll("details[open]")].map((details) => details.parentElement.dataset.eventId));
    const fragment = document.createDocumentFragment();
    for (const event of filtered) {
      const item = eventItem(event, openIds.has(event.event_id));
      item.dataset.eventId = event.event_id;
      fragment.append(item);
    }
    node("event-list").replaceChildren(fragment);
    node("event-count").textContent = count(filtered.length);
    emptyState("events-empty", events.length ? "Bu filtreyle eşleşen olay yok" : "Henüz olay toplanmadı", events.length ? "Aramayı veya olay türünü değiştirerek yeniden dene." : "Şimdi tara ile Windows günlüklerini kontrol et. Erişilebilen yeni kayıtlar burada görünecek.", !filtered.length);
  }

  function alertItem(alert) {
    const severity = Object.hasOwn(severityNames, alert.severity) ? alert.severity : "low";
    const item = element("li", "alert-item");
    const button = element("button", `alert-button ${severity}`);
    button.type = "button";
    const title = alertNames[alert.rule_id] || alert.title || alert.rule_id;
    button.setAttribute("aria-label", `${title}. Kanıtları incele.`);
    const top = element("div", "alert-topline");
    const time = element("time", "event-time", formatDate(alert.timestamp, dateFormat));
    time.dateTime = alert.timestamp || "";
    top.append(element("span", `severity-badge ${severity}`, severityNames[severity]), time);
    const meta = element("div", "alert-meta");
    const group = alert.group || {};
    meta.append(element("span", "", group.device_id || "Cihaz ayrıntısı kanıtlarda"));
    if (group["attributes.user"]) meta.append(element("span", "", `· ${group["attributes.user"]}`));
    if (alert.synthetic) meta.append(element("span", "synthetic-badge", "SENTETİK"));
    const bottom = element("div", "alert-bottomline");
    bottom.append(element("span", "rule-label", alert.rule_id), element("span", "evidence-link", `${count(alert.matched_count)} kayıt · İncele →`));
    button.append(top, element("h3", "alert-title", title), meta, bottom);
    button.addEventListener("click", () => showEvidence(alert));
    item.append(button);
    return item;
  }

  function renderAlerts() {
    if (!state.data) return;
    const alerts = Array.isArray(state.data.alerts) ? state.data.alerts : [];
    const query = node("search-input").value.trim().toLocaleLowerCase("tr-TR");
    const severity = node("severity-filter").value;
    const filtered = alerts.filter((alert) => (!severity || alert.severity === severity) && searchMatches([alert, alertNames[alert.rule_id]], query));
    const fingerprint = JSON.stringify([alerts.map((alert) => alert.alert_id), query, severity]);
    if (state.renderedAlerts === fingerprint) return;
    state.renderedAlerts = fingerprint;
    const fragment = document.createDocumentFragment();
    for (const alert of filtered) fragment.append(alertItem(alert));
    node("alert-list").replaceChildren(fragment);
    node("alert-count").textContent = count(filtered.length);
    emptyState("alerts-empty", alerts.length ? "Bu filtreyle eşleşen alarm yok" : "Henüz kural eşleşmesi yok", alerts.length ? "Aramayı veya önem düzeyini değiştirerek yeniden dene." : "Toplanan kayıtlarda bir tespit kuralı eşleştiğinde alarm burada görünür. Bu, sistemin bütünüyle güvenli olduğu anlamına gelmez.", !filtered.length);
  }

  function syncKindOptions(events) {
    const select = node("event-kind-filter");
    if (document.activeElement === select) return;
    const previous = select.value;
    const kinds = [...new Set(events.map((event) => event.kind).filter(Boolean))].sort();
    const fragment = document.createDocumentFragment();
    const all = element("option", "", "Tüm olay türleri");
    all.value = "";
    fragment.append(all);
    for (const kind of kinds) {
      const option = element("option", "", kindNames[kind] || kind);
      option.value = kind;
      fragment.append(option);
    }
    select.replaceChildren(fragment);
    select.value = kinds.includes(previous) ? previous : "";
  }

  async function refresh() {
    if (state.fetching) return;
    state.fetching = true;
    try {
      const data = await api("/api/state");
      state.data = data;
      const summary = data.summary || {};
      node("events-total").textContent = count(summary.events_total);
      node("events-day").textContent = count(summary.events_24h);
      node("alerts-total").textContent = count(summary.alerts_total);
      node("alerts-day").textContent = count(summary.alerts_24h);
      node("alerts-total").closest(".metric-card").classList.toggle("has-alerts", summary.alerts_total > 0);
      node("app-version").textContent = data.version ? `v${data.version}` : "";
      const lastScan = node("last-scan");
      lastScan.textContent = data.last_scan_at ? formatDate(data.last_scan_at, timeFormat) : "henüz yapılmadı";
      lastScan.dateTime = data.last_scan_at || "";
      lastScan.title = data.last_scan_at ? formatDate(data.last_scan_at) : "";
      renderHealth(data.health || {}, data.monitor || {});
      renderSources(Array.isArray(data.sources) ? data.sources : [], data.monitor || {}, data.health || {});
      syncKindOptions(Array.isArray(data.events) ? data.events : []);
      renderEvents();
      renderAlerts();
      node("connection-status").textContent = "Panel bağlı";
      node("connection-status").className = "connection-badge";
      notice("error-notice", data.monitor?.last_error ? "Windows günlükleri okunurken bir sorun oluştu. Kaynak durumlarını kontrol et; otomatik izleme yeniden deneyecek." : "");
    } catch {
      node("connection-status").textContent = "Panel bağlantısı kesildi";
      node("connection-status").className = "connection-badge offline";
      node("health-title").textContent = "Kaynak durumu güncellenemiyor";
      node("health-summary").textContent = "Yerel izleyiciyle bağlantı kurulamadığı için kaynakların son durumunu doğrulayamıyoruz. Görünen kayıtlar önceki yüklemeden kalmış olabilir.";
      node("health-next").textContent = "Uygulamanın açık olduğunu kontrol et. Bağlantı geldiğinde görünüm yenilenecek.";
      node("health-badge").textContent = "Güncel değil";
      node("health-badge").className = "health-badge error";
      notice("error-notice", "Yerel izleyiciye ulaşılamıyor. Uygulamanın açık olduğunu kontrol et. Bağlantı geldiğinde görünüm kendiliğinden yenilenecek.");
    } finally {
      state.fetching = false;
    }
  }

  async function scan() {
    if (state.scanning) return;
    state.scanning = true;
    node("scan-button").disabled = true;
    node("scan-button").classList.add("scanning");
    node("scan-button").setAttribute("aria-busy", "true");
    node("scan-button-label").textContent = "Taranıyor";
    notice("scan-notice", "Windows günlükleri kontrol ediliyor. Bu işlem kısa bir süre alabilir.");
    try {
      const previousScan = state.data?.last_scan_at || null;
      const result = await api("/api/scan", { method: "POST", headers: { "X-Sentinel-Token": token } });
      notice("scan-notice", result.status === "busy" ? "Bir tarama zaten sürüyor. Tamamlandığında kayıtlar güncellenecek." : "Tarama başlatıldı. Windows günlüklerinin okunması bekleniyor…");
      let completed = false;
      for (let attempt = 0; attempt < 90; attempt += 1) {
        await new Promise((resolve) => window.setTimeout(resolve, 1000));
        await refresh();
        const monitor = state.data?.monitor || {};
        if (!monitor.scanning && monitor.last_error) throw new Error("Windows günlükleri okunamadı. Kaynak durumlarını kontrol edip yeniden dene.");
        if (!monitor.scanning && state.data?.last_scan_at && state.data.last_scan_at !== previousScan) {
          completed = true;
          break;
        }
      }
      notice("scan-notice", completed ? "Tarama tamamlandı. Yeni kayıtlar ve eşleşen alarmlar güncellendi." : "Tarama beklenenden uzun sürüyor. Görünüm yenilenmeye devam edecek; izleyici durumunu kaynak bağlantılarından kontrol edebilirsin.");
    } catch (error) {
      notice("scan-notice", "");
      notice("error-notice", error.name === "AbortError" ? "Tarama yanıtı gecikti. İzleyicinin durumunu kontrol et; görünüm yenilenmeye devam edecek." : error.message);
    } finally {
      state.scanning = false;
      node("scan-button").disabled = false;
      node("scan-button").classList.remove("scanning");
      node("scan-button").removeAttribute("aria-busy");
      node("scan-button-label").textContent = "Şimdi tara";
    }
  }

  async function showEvidence(alert) {
    const dialog = node("evidence-dialog");
    const body = node("evidence-body");
    const request = ++state.evidenceRequest;
    body.replaceChildren(element("p", "", "Alarmın dayandığı kayıtlar yükleniyor…"));
    if (!dialog.open) dialog.showModal();
    if (!/^[a-f0-9]{64}$/.test(alert.alert_id || "")) {
      body.replaceChildren(element("p", "evidence-error", "Bu alarmın kayıt kimliği geçerli değil."));
      return;
    }
    try {
      const data = await api(`/api/alerts/${alert.alert_id}/evidence`);
      if (request !== state.evidenceRequest || !dialog.open) return;
      const current = data.alert || alert;
      const events = Array.isArray(data.events) ? data.events : [];
      const grid = element("dl", "details-grid");
      addDetail(grid, "Kural", current.rule_id);
      addDetail(grid, "Önem", severityNames[current.severity] || current.severity);
      addDetail(grid, "İlk kayıt", formatDate(current.window_start));
      addDetail(grid, "Son kayıt", formatDate(current.window_end));
      addDetail(grid, "Eşleşen kayıt", count(current.matched_count));
      addDetail(grid, "Veri", current.synthetic ? "Sentetik örnek" : "Gerçek Windows kayıtları");
      addDetail(grid, "Alarm kimliği", current.alert_id, true);
      body.replaceChildren(element("h3", "", alertNames[current.rule_id] || current.title || current.rule_id), grid);
      if (events.length < (current.event_ids || []).length) body.append(element("p", "evidence-note", "Bazı kanıt kayıtları bu çalışma alanında artık bulunmuyor. Erişilebilen kayıtlar aşağıda gösteriliyor."));
      body.append(element("h3", "", `Dayanak kayıtlar · ${count(events.length)}`));
      const list = element("ol", "event-list");
      for (const event of events) list.append(eventItem(event, events.length <= 3));
      body.append(list);
      if (!events.length) body.append(element("p", "evidence-note", "Bu alarm için erişilebilir olay kaydı bulunamadı."));
    } catch (error) {
      if (request !== state.evidenceRequest || !dialog.open) return;
      body.replaceChildren(element("p", "evidence-error", error.message || "Alarm kayıtları yüklenemedi. Pencereyi kapatıp yeniden dene."));
    }
  }

  node("scan-button").addEventListener("click", scan);
  node("search-input").addEventListener("input", () => { renderEvents(); renderAlerts(); });
  node("event-kind-filter").addEventListener("change", renderEvents);
  node("severity-filter").addEventListener("change", renderAlerts);
  node("close-evidence").addEventListener("click", () => node("evidence-dialog").close());
  node("evidence-dialog").addEventListener("close", () => { state.evidenceRequest += 1; });
  document.addEventListener("visibilitychange", () => { if (!document.hidden) refresh(); });
  refresh();
  window.setInterval(() => { if (!document.hidden && !state.scanning) refresh(); }, 5000);
})();
