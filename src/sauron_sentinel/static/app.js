"use strict";

(() => {
  const node = (id) => document.getElementById(id);
  const token = document.querySelector('meta[name="sentinel-token"]')?.content || "";
  const severityNames = { critical: "Kritik", high: "Yüksek", medium: "Orta", low: "Düşük" };
  const reviewNames = { new: "Yeni", reviewed: "İncelendi", expected: "Beklediğim işlem" };
  const reviewNoteLimit = 500;
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
  const state = {
    data: null, fetching: false, scanning: false, evidenceRequest: 0, activeEvidence: null,
    evidenceReturnId: null, reviewRevision: 0, reviewOverrides: new Map(), pendingReviews: new Map(),
    readRevision: 0, readOverrides: new Map(), pendingReads: new Map(),
    preferences: null, preferencesDirty: false, preferencesSaving: false, preferenceRevision: 0,
    preferenceOverride: null, notificationTesting: false, connected: false,
    renderedEvents: "", renderedAlerts: "", renderedSources: "",
  };
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
        const message = response.status === 403 ? "Oturum doğrulanamadı. Sayfayı yenileyip tekrar dene."
          : response.status === 409 ? "Bir tarama zaten sürüyor. Birkaç saniye sonra yeniden dene."
            : explanation || `İşlem tamamlanamadı (${response.status}).`;
        const error = new Error(message);
        error.status = response.status;
        error.code = explanation;
        throw error;
      }
      return await response.json();
    } finally {
      window.clearTimeout(timer);
    }
  }

  function validPreferences(value) {
    return value?.schema_version === 1 && typeof value.notifications_enabled === "boolean"
      && ["low", "medium", "high"].includes(value.minimum_severity)
      && Number.isInteger(value.scan_interval_seconds) && value.scan_interval_seconds >= 5 && value.scan_interval_seconds <= 3600;
  }

  function preferenceDraft() {
    return {
      schema_version: 1, notifications_enabled: node("notifications-enabled").checked,
      minimum_severity: node("minimum-severity").value, scan_interval_seconds: Number(node("scan-interval").value),
    };
  }

  function samePreferences(first, second) {
    return validPreferences(first) && validPreferences(second) && first.notifications_enabled === second.notifications_enabled
      && first.minimum_severity === second.minimum_severity && first.scan_interval_seconds === second.scan_interval_seconds;
  }

  function setPreferenceDraft(preferences) {
    const select = node("scan-interval");
    const fragment = document.createDocumentFragment();
    for (const [seconds, label] of [[15, "15 saniye"], [30, "30 saniye"], [60, "1 dakika"], [300, "5 dakika"]]) {
      const option = element("option", "", label);
      option.value = String(seconds);
      fragment.append(option);
    }
    if (![15, 30, 60, 300].includes(preferences.scan_interval_seconds)) {
      const custom = element("option", "", `${count(preferences.scan_interval_seconds)} saniye (özel)`);
      custom.value = String(preferences.scan_interval_seconds);
      fragment.append(custom);
    }
    select.replaceChildren(fragment);
    select.value = String(preferences.scan_interval_seconds);
    node("notifications-enabled").checked = preferences.notifications_enabled;
    node("minimum-severity").value = preferences.minimum_severity;
  }

  function updatePreferenceControls() {
    const waiting = !state.preferences || !state.connected || !token;
    const busy = state.preferencesSaving || state.notificationTesting;
    for (const id of ["notifications-enabled", "minimum-severity", "scan-interval"]) node(id).disabled = waiting || busy;
    node("save-preferences").disabled = waiting || busy || !state.preferencesDirty;
    node("save-preferences").textContent = state.preferencesSaving ? "Kaydediliyor…" : "Ayarları kaydet";
    node("preferences-form").setAttribute("aria-busy", state.preferencesSaving ? "true" : "false");
    node("test-notification").disabled = waiting || busy || state.preferencesDirty
      || !state.preferences?.notifications_enabled || state.data?.notifications?.available !== true;
    node("test-notification").textContent = state.notificationTesting ? "Deneniyor…" : "Deneme bildirimi";
    node("test-notification").setAttribute("aria-busy", state.notificationTesting ? "true" : "false");
    node("scan-button").disabled = state.scanning || !state.connected || !token;
  }

  function renderPreferences(data) {
    const preferences = state.preferenceOverride?.preferences || data.preferences;
    if (validPreferences(preferences)) {
      const replaceDraft = !state.preferences || (!state.preferencesDirty && !state.preferencesSaving);
      state.preferences = preferences;
      if (replaceDraft) setPreferenceDraft(preferences);
      state.preferencesDirty = !samePreferences(preferenceDraft(), preferences);
      node("preferences-summary").textContent = `Bildirimler ${preferences.notifications_enabled ? "açık" : "kapalı"} · ${count(preferences.scan_interval_seconds)} sn`;
      if (!node("preferences-error").textContent && !state.preferencesDirty && !state.preferencesSaving
        && node("preferences-feedback").textContent === "Ayarlar yükleniyor…") {
        node("preferences-feedback").textContent = "Kaydedilen ayarlar gösteriliyor.";
      }
    }
    // Keep this notice visible for the session, including after a successful save.
    if (data.preferences_status === "reset_invalid" && node("preferences-reset").hidden) {
      node("preferences-reset").hidden = false;
      node("preferences-panel").open = true;
    }
    const notifications = data.notifications || {};
    node("notification-capability").textContent = notifications.available === true
      ? "Windows bildirim desteği kullanılabilir. Deneme bildirimi alarm oluşturmaz; önce ayarlarını kaydet."
      : "Windows bildirimi için masaüstü bildirim desteği gerekir; bu oturumda kullanılamıyor. Alarmları bu panelden izleyebilirsin.";
    const attempt = { attempting: "gönderim deneniyor", queued: "uygulamanın bildirim kuyruğuna alındı; Windows’ta görüntülendiği doğrulanamaz", failed: "gönderim tamamlanamadı" }[notifications.last_attempt_status];
    const deliveryError = {
      unsupported_platform: "Windows bildirimleri bu işletim sisteminde kullanılamıyor.",
      not_initialized: "Masaüstü bildirim desteği henüz hazır değil.",
      native_unavailable: "Windows bildirim desteği kullanılamıyor.",
      notification_failed: "Bildirim gönderimi tamamlanamadı.",
    }[notifications.last_error];
    const attemptTime = notifications.last_attempt_at ? ` · ${formatDate(notifications.last_attempt_at)}` : "";
    notice("notification-last-attempt", deliveryError ? `${deliveryError} Alarmları panelden izleyebilirsin.${attemptTime}`
      : attempt ? `Son bildirim denemesi: ${attempt}${attemptTime}.` : "");
    node("notification-last-attempt").classList.toggle("failed", Boolean(deliveryError));
    if (!token) notice("preferences-error", "Oturum doğrulanamadı. Ayarları değiştirmek için sayfayı yenile.");
    updatePreferenceControls();
  }

  function preferencesChanged() {
    state.preferencesDirty = !samePreferences(preferenceDraft(), state.preferences);
    notice("preferences-error", "");
    node("preferences-feedback").textContent = state.preferencesDirty ? "Değişiklikler henüz kaydedilmedi. Deneme için önce ayarları kaydet." : "Kaydedilen ayarlar gösteriliyor.";
    node("preferences-feedback").className = "preferences-feedback";
    notice("notification-test-feedback", "");
    notice("notification-test-error", "");
    updatePreferenceControls();
  }

  async function savePreferences(event) {
    event.preventDefault();
    if (state.preferencesSaving || state.notificationTesting || !state.connected || !token || !state.preferences) return;
    const preferences = preferenceDraft();
    if (!validPreferences(preferences)) {
      notice("preferences-error", "Ayarlar geçerli değil. Önem düzeyini ve tarama aralığını kontrol et.");
      return;
    }
    state.preferencesSaving = true;
    notice("preferences-error", "");
    node("preferences-feedback").textContent = "Ayarlar kaydediliyor…";
    node("preferences-feedback").className = "preferences-feedback";
    updatePreferenceControls();
    try {
      const result = await api("/api/preferences", {
        method: "POST", headers: { "Content-Type": "application/json", "X-Sentinel-Token": token }, body: JSON.stringify(preferences),
      });
      if (!validPreferences(result.preferences) || result.preferences_status !== "ok") throw new Error("invalid_preferences_response");
      state.preferenceRevision += 1;
      state.preferenceOverride = { preferences: result.preferences, revision: state.preferenceRevision };
      state.preferences = result.preferences;
      setPreferenceDraft(result.preferences);
      state.preferencesDirty = false;
      renderPreferences(state.data || {});
      node("preferences-feedback").textContent = "Ayarlar kaydedildi. Uygulamayı yeniden açtığında korunur.";
      node("preferences-feedback").className = "preferences-feedback saved";
    } catch (error) {
      node("preferences-feedback").textContent = "";
      notice("preferences-error", error.status === 403 ? "Oturum doğrulanamadı. Sayfayı yenileyip tekrar dene."
        : error.code === "invalid_preferences" ? "Ayarlar kabul edilmedi. Seçimlerini kontrol edip yeniden dene."
          : "Ayarların kaydedildiği doğrulanamadı. Seçimlerin bu formda duruyor; yeniden kaydetmeyi deneyebilirsin.");
    } finally {
      state.preferencesSaving = false;
      updatePreferenceControls();
    }
  }

  async function testNotification() {
    if (node("test-notification").disabled || state.notificationTesting) return;
    state.notificationTesting = true;
    notice("notification-test-error", "");
    notice("notification-test-feedback", "Deneme bildirimi gönderilmeye çalışılıyor. Bu bir alarm değildir.");
    updatePreferenceControls();
    try {
      const result = await api("/api/notifications/test", {
        method: "POST", headers: { "Content-Type": "application/json", "X-Sentinel-Token": token }, body: "{}",
      });
      if (result.status !== "queued") throw new Error("invalid_notification_response");
      notice("notification-test-feedback", "Deneme uygulamanın bildirim kuyruğuna alındı. Bu bir alarm değildir. Windows bildirimi göstermeyebilir; teslim edildiği doğrulanamaz.");
    } catch (error) {
      notice("notification-test-feedback", "");
      const message = error.status === 403 ? "Oturum doğrulanamadı. Sayfayı yenileyip tekrar dene."
        : error.code === "notifications_disabled" ? "Windows bildirimleri kapalı. Bildirimleri açıp ayarları kaydet."
          : error.code === "notifications_unavailable" ? "Bu oturumda Windows bildirim desteği kullanılamıyor. Alarmları panelden izleyebilirsin."
            : "Deneme bildiriminin gönderildiği doğrulanamadı. Windows bildirim ayarlarını kontrol edip yeniden deneyebilirsin.";
      notice("notification-test-error", message);
    } finally {
      state.notificationTesting = false;
      updatePreferenceControls();
    }
  }

  function unreadFor(alert) {
    return state.readOverrides.has(alert.alert_id) ? false : alert.unread === true;
  }

  function renderUnreadCount() {
    const total = state.data?.notifications?.unread_count;
    const available = Number.isInteger(total) && total >= 0;
    const alerts = Array.isArray(state.data?.alerts) ? state.data.alerts : [];
    // Apply only reads missing from this snapshot. Older replies cannot hide
    // newly collected alarms or put a completed read back into the count.
    const newlyRead = alerts.filter((alert) => alert.unread === true && state.readOverrides.has(alert.alert_id)).length;
    notice("unread-count", available ? `${count(Math.max(0, total - newlyRead))} okunmadı` : "");
  }

  function persistRead(alertId) {
    if (state.pendingReads.has(alertId)) return state.pendingReads.get(alertId);
    const operation = (async () => {
      const result = await api(`/api/alerts/${alertId}/read`, {
        method: "POST", headers: { "Content-Type": "application/json", "X-Sentinel-Token": token }, body: "{}",
      });
      if (result.unread !== false || !Number.isInteger(result.unread_count) || result.unread_count < 0) throw new Error("invalid_read_response");
      state.readRevision += 1;
      state.readOverrides.set(alertId, { revision: state.readRevision });
      renderAlerts();
      renderUnreadCount();
      return result;
    })();
    state.pendingReads.set(alertId, operation);
    operation.finally(() => { if (state.pendingReads.get(alertId) === operation) state.pendingReads.delete(alertId); }).catch(() => {});
    return operation;
  }

  async function markEvidenceRead(alertId, request, feedback, retry) {
    const current = () => evidenceIsCurrent(request, alertId) && node("evidence-body").contains(feedback);
    if (!current()) return;
    if (!token) {
      feedback.textContent = "Ayrıntılar açıldı; okundu bilgisini saklamak için oturum doğrulanamadı. Sayfayı yenile.";
      return;
    }
    retry.hidden = true;
    feedback.textContent = "Okundu bilgisi kaydediliyor…";
    feedback.className = "evidence-read-status";
    try {
      if (!state.readOverrides.has(alertId)) await persistRead(alertId);
      if (current()) feedback.textContent = "Okundu bilgisi kaydedildi. Değerlendirmen ayrıca saklanır.";
    } catch (error) {
      if (!current()) return;
      feedback.textContent = error.status === 403 ? "Okundu bilgisi kaydedilemedi. Oturum için sayfayı yenile."
        : error.status === 404 ? "Alarm artık bulunamadığı için okundu bilgisi kaydedilemedi."
          : "Ayrıntılar açıldı; okundu bilgisi kaydedilemedi. Yeniden deneyebilirsin.";
      feedback.className = "evidence-read-status failed";
      retry.hidden = error.status === 403 || error.status === 404;
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
    button.dataset.alertId = alert.alert_id;
    const title = alertNames[alert.rule_id] || alert.title || alert.rule_id;
    const review = reviewFor(alert);
    const unread = unreadFor(alert);
    button.classList.toggle("unread", unread);
    button.setAttribute("aria-label", `${title}. ${unread ? "Okunmadı. " : ""}${reviewNames[review.status]}. Açıklamayı ve kayıtları incele.`);
    const top = element("div", "alert-topline");
    const time = element("time", "event-time", formatDate(alert.timestamp, dateFormat));
    time.dateTime = alert.timestamp || "";
    const badges = element("div", "alert-badges");
    badges.append(element("span", `severity-badge ${severity}`, severityNames[severity]), element("span", `review-badge ${review.status}`, reviewNames[review.status]));
    if (unread) badges.append(element("span", "unread-marker", "Okunmadı"));
    top.append(badges, time);
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
    const filtered = alerts.filter((alert) => (!severity || alert.severity === severity) && searchMatches([{ ...alert, review: reviewFor(alert) }, alertNames[alert.rule_id], reviewNames[reviewFor(alert).status]], query));
    const fingerprint = JSON.stringify([alerts.map((alert) => [alert.alert_id, reviewFor(alert), unreadFor(alert)]), query, severity]);
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
    const reviewRevision = state.reviewRevision;
    const readRevision = state.readRevision;
    const preferenceRevision = state.preferenceRevision;
    try {
      const data = await api("/api/state");
      // A response requested before a save must not put the previous review back.
      for (const [alertId, saved] of state.reviewOverrides) {
        if (saved.revision <= reviewRevision) state.reviewOverrides.delete(alertId);
      }
      for (const [alertId, saved] of state.readOverrides) {
        if (saved.revision <= readRevision) state.readOverrides.delete(alertId);
      }
      if (state.preferenceOverride?.revision <= preferenceRevision) state.preferenceOverride = null;
      state.data = data;
      state.connected = true;
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
      renderUnreadCount();
      renderPreferences(data);
      node("connection-status").textContent = "Panel bağlı";
      node("connection-status").className = "connection-badge";
      notice("error-notice", data.monitor?.last_error ? "Windows günlükleri okunurken bir sorun oluştu. Kaynak durumlarını kontrol et; otomatik izleme yeniden deneyecek." : "");
    } catch {
      state.connected = false;
      updatePreferenceControls();
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
    if (state.scanning || !state.connected || !token) return;
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
      updatePreferenceControls();
      node("scan-button").classList.remove("scanning");
      node("scan-button").removeAttribute("aria-busy");
      node("scan-button-label").textContent = "Şimdi tara";
    }
  }

  function validReview(review) {
    return review && typeof review.status === "string" && Object.hasOwn(reviewNames, review.status) && typeof review.note === "string"
      && Array.from(review.note).length <= reviewNoteLimit
      && (review.updated_at === null || typeof review.updated_at === "string");
  }

  function reviewFor(alert) {
    const review = state.reviewOverrides.get(alert.alert_id)?.review || alert.review;
    return validReview(review) ? review : { status: "new", note: "", updated_at: null };
  }

  function evidenceIsCurrent(request, alertId) {
    return request === state.evidenceRequest && state.activeEvidence?.alertId === alertId && node("evidence-dialog").open;
  }

  function reviewNoteError(value) {
    if (Array.from(value).length > reviewNoteLimit) return "Not en fazla 500 karakter olabilir. Kaydetmek için notu kısalt.";
    if (/[\p{Cc}\p{Cf}\p{Cs}]/u.test(value.replace(/[\n\t]/g, ""))) return "Notta görünmeyen denetim karakterleri var. Bunları kaldırıp yeniden dene.";
    return "";
  }

  function explanationSection(title, content, ordered = false) {
    const section = element("section", "explanation-section");
    section.append(element("h3", "", title));
    if (Array.isArray(content)) {
      const list = element(ordered ? "ol" : "ul", "explanation-list");
      for (const item of content) list.append(element("li", "", item));
      section.append(list);
    } else {
      section.append(element("p", "", content));
    }
    return section;
  }

  function explanationFor(alert, explanation) {
    const content = explanation?.schema_version === 1 && explanation.rule_id === alert.rule_id ? explanation : {};
    const strings = (values) => Array.isArray(values) ? values.filter((value) => typeof value === "string" && value.trim()) : [];
    const benign = strings(content.benign_causes);
    const checks = strings(content.checks);
    const explanationView = element("div", "alarm-explanation");
    explanationView.append(
      explanationSection("Ne oldu?", typeof content.summary === "string" && content.summary ? content.summary : "Bu alarmın açıklaması alınamadı. Erişilebilen dayanak kayıtları aşağıda inceleyebilirsin."),
      explanationSection("Neden alarm oluştu?", typeof content.why === "string" && content.why ? content.why : "Kuralın eşleşme açıklaması alınamadı. Alarm ve kural bilgilerini aşağıdan kontrol edebilirsin."),
      explanationSection("Olası normal nedenler", benign.length ? benign : "Bu alarm için olası normal nedenler belirtilmedi."),
      explanationSection("Ne kontrol edebilirim?", checks.length ? checks : "Olayın saatini ve ilgili kullanıcıyı, o sırada yaptığın işlemlerle karşılaştır. Emin değilsen yetkili birinden destek al.", true),
    );
    return explanationView;
  }

  function reviewForm(alert, review, request) {
    const section = element("section", "review-section");
    section.setAttribute("aria-labelledby", "review-title");
    const heading = element("h3", "", "Bu alarm için değerlendirmen");
    heading.id = "review-title";
    section.append(heading, element("p", "review-scope", "Seçimin yalnızca bu alarm için saklanır. Sonraki benzer olaylar yine alarm oluşturabilir."));
    const form = element("form", "review-form");
    form.noValidate = true;
    const statusLabel = element("label", "review-label", "Değerlendirme");
    statusLabel.htmlFor = "review-select";
    const select = element("select", "review-select");
    select.id = "review-select";
    select.name = "status";
    for (const [value, name] of Object.entries(reviewNames)) {
      const option = element("option", "", name);
      option.value = value;
      select.append(option);
    }
    select.value = review.status;
    const noteLabel = element("label", "review-label", "Kısa not (isteğe bağlı)");
    noteLabel.htmlFor = "review-note";
    const note = element("textarea", "review-note");
    note.id = "review-note";
    note.name = "note";
    note.rows = 3;
    note.value = review.note;
    note.setAttribute("aria-describedby", "review-note-help review-note-count review-note-error");
    const helpRow = element("div", "review-note-help");
    const help = element("p", "", "En fazla 500 karakter. Not bu bilgisayarda saklanır.");
    help.id = "review-note-help";
    const counter = element("output", "review-note-count");
    counter.id = "review-note-count";
    counter.htmlFor = note.id;
    helpRow.append(help, counter);
    const validation = element("p", "review-error");
    validation.id = "review-note-error";
    validation.setAttribute("role", "alert");
    const actions = element("div", "review-actions");
    const save = element("button", "button button-primary", "Değerlendirmeyi kaydet");
    save.type = "submit";
    const savedAt = element("p", "review-saved-at");
    const feedback = element("p", "review-feedback");
    feedback.setAttribute("role", "status");
    feedback.setAttribute("aria-live", "polite");
    const failure = element("p", "review-error");
    failure.setAttribute("role", "alert");
    actions.append(save, savedAt);
    form.append(statusLabel, select, noteLabel, note, helpRow, validation, actions, feedback, failure);
    section.append(form);
    let savedReview = review;
    let busy = false;
    const current = () => evidenceIsCurrent(request, alert.alert_id) && node("evidence-body").contains(form);
    function update() {
      const error = reviewNoteError(note.value);
      counter.textContent = `${count(Array.from(note.value).length)} / 500`;
      counter.classList.toggle("over-limit", Boolean(error));
      validation.textContent = error;
      validation.hidden = !error;
      note.setAttribute("aria-invalid", error ? "true" : "false");
      select.disabled = busy || !token;
      note.disabled = busy || !token;
      save.disabled = busy || !token || Boolean(error);
      save.textContent = busy ? "Kaydediliyor…" : "Değerlendirmeyi kaydet";
      form.setAttribute("aria-busy", busy ? "true" : "false");
      savedAt.textContent = savedReview.updated_at ? `Son kayıt: ${formatDate(savedReview.updated_at)}` : "Henüz değerlendirme kaydedilmedi.";
    }
    const changed = () => {
      failure.textContent = "";
      feedback.textContent = select.value !== savedReview.status || note.value !== savedReview.note ? "Değişiklikler henüz kaydedilmedi." : "";
      feedback.className = "review-feedback";
      update();
    };
    select.addEventListener("change", changed);
    note.addEventListener("input", changed);
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (busy || !token || !current()) return;
      const payload = { status: select.value, note: note.value };
      if (!Object.hasOwn(reviewNames, payload.status) || reviewNoteError(payload.note)) {
        update();
        note.focus();
        return;
      }
      busy = true;
      failure.textContent = "";
      feedback.textContent = "Değerlendirme kaydediliyor…";
      feedback.className = "review-feedback";
      update();
      const operation = api(`/api/alerts/${alert.alert_id}/review`, {
        method: "POST", headers: { "Content-Type": "application/json", "X-Sentinel-Token": token }, body: JSON.stringify(payload),
      });
      state.pendingReviews.set(alert.alert_id, operation);
      try {
        const result = await operation;
        if (!validReview(result.review)) throw new Error("invalid_review_response");
        state.reviewRevision += 1;
        state.reviewOverrides.set(alert.alert_id, { review: result.review, revision: state.reviewRevision });
        renderAlerts();
        if (!current()) return;
        savedReview = result.review;
        select.value = savedReview.status;
        note.value = savedReview.note;
        feedback.textContent = "Değerlendirme kaydedildi.";
        feedback.className = "review-feedback saved";
      } catch (error) {
        if (!current()) return;
        feedback.textContent = "";
        failure.textContent = error.status === 403 ? "Oturum doğrulanamadı. Sayfayı yenileyip tekrar dene."
          : error.status === 404 ? "Bu alarm artık bulunamıyor. Pencereyi kapatıp alarm listesini kontrol et."
            : error.code === "invalid_review" ? "Değerlendirme kabul edilmedi. Durumu ve en fazla 500 karakterlik notunu kontrol edip yeniden dene."
              : "Kaydedildiği doğrulanamadı. Notun bu pencerede duruyor; yeniden kaydetmeyi deneyebilirsin.";
      } finally {
        if (state.pendingReviews.get(alert.alert_id) === operation) state.pendingReviews.delete(alert.alert_id);
        if (current()) { busy = false; update(); }
      }
    });
    update();
    return section;
  }

  async function showEvidence(alert) {
    const dialog = node("evidence-dialog");
    const body = node("evidence-body");
    const request = ++state.evidenceRequest;
    state.activeEvidence = { alertId: alert.alert_id, request };
    state.evidenceReturnId = /^[a-f0-9]{64}$/.test(alert.alert_id || "") ? alert.alert_id : null;
    body.setAttribute("aria-busy", "true");
    body.replaceChildren(element("p", "", "Alarmın dayandığı kayıtlar yükleniyor…"));
    if (!dialog.open) {
      dialog.showModal();
      node("evidence-title").focus();
    }
    if (!/^[a-f0-9]{64}$/.test(alert.alert_id || "")) {
      body.replaceChildren(element("p", "evidence-error", "Bu alarmın kayıt kimliği geçerli değil."));
      body.removeAttribute("aria-busy");
      return;
    }
    try {
      // Reopening a saving alert reads the result after that write has settled.
      const pending = state.pendingReviews.get(alert.alert_id);
      if (pending) {
        body.replaceChildren(element("p", "", "Kaydetme tamamlanıyor; alarmın güncel durumu yükleniyor…"));
        try { await pending; } catch { /* The fresh read also resolves uncertain saves. */ }
        if (!evidenceIsCurrent(request, alert.alert_id)) return;
      }
      const data = await api(`/api/alerts/${alert.alert_id}/evidence`);
      if (!evidenceIsCurrent(request, alert.alert_id)) return;
      const current = data.alert || alert;
      if (current.alert_id !== alert.alert_id) throw new Error("invalid_evidence_response");
      const events = Array.isArray(data.events) ? data.events : [];
      const grid = element("dl", "details-grid");
      addDetail(grid, "Kural", current.rule_id);
      addDetail(grid, "Önem", severityNames[current.severity] || current.severity);
      addDetail(grid, "İlk kayıt", formatDate(current.window_start));
      addDetail(grid, "Son kayıt", formatDate(current.window_end));
      addDetail(grid, "Eşleşen kayıt", count(current.matched_count));
      addDetail(grid, "Veri", current.synthetic ? "Sentetik örnek" : "Gerçek Windows kayıtları");
      addDetail(grid, "Alarm kimliği", current.alert_id, true);
      const technical = element("details", "evidence-technical");
      technical.append(element("summary", "", "Alarm ve kural bilgileri"), grid);
      const review = state.reviewOverrides.get(current.alert_id)?.review || data.review;
      body.replaceChildren(
        element("h3", "evidence-alert-title", alertNames[current.rule_id] || current.title || current.rule_id),
        element("p", "evidence-caution", "Alarm bir kural eşleşmesidir; tek başına saldırı olduğunu göstermez."),
        explanationFor(current, data.explanation),
        reviewForm(current, validReview(review) ? review : { status: "new", note: "", updated_at: null }, request),
        technical,
      );
      if (events.length < (current.event_ids || []).length) body.append(element("p", "evidence-note", "Bazı kanıt kayıtları bu çalışma alanında artık bulunmuyor. Erişilebilen kayıtlar aşağıda gösteriliyor."));
      body.append(element("h3", "", `Dayanak kayıtlar · ${count(events.length)}`));
      const list = element("ol", "event-list");
      for (const event of events) list.append(eventItem(event, events.length <= 3));
      body.append(list);
      if (!events.length) body.append(element("p", "evidence-note", "Bu alarm için erişilebilir olay kaydı bulunamadı."));
      if (data.unread === true) {
        const readRow = element("div", "evidence-read-row");
        const readFeedback = element("p", "evidence-read-status");
        readFeedback.setAttribute("role", "status");
        readFeedback.setAttribute("aria-live", "polite");
        const retry = element("button", "button button-secondary", "Okundu bilgisini yeniden kaydet");
        retry.type = "button";
        retry.hidden = true;
        retry.addEventListener("click", () => markEvidenceRead(current.alert_id, request, readFeedback, retry));
        readRow.append(readFeedback, retry);
        body.append(readRow);
        body.removeAttribute("aria-busy");
        await markEvidenceRead(current.alert_id, request, readFeedback, retry);
      }
    } catch (error) {
      if (!evidenceIsCurrent(request, alert.alert_id)) return;
      const message = error.status === 403 ? "Oturum doğrulanamadı. Sayfayı yenileyip tekrar dene."
        : error.status === 404 ? "Bu alarm artık bulunamıyor. Pencereyi kapatıp alarm listesini kontrol et."
          : "Alarm bilgileri yüklenemedi. Pencereyi kapatıp yeniden dene.";
      const failure = element("p", "evidence-error", message);
      failure.setAttribute("role", "alert");
      body.replaceChildren(failure);
    } finally {
      if (evidenceIsCurrent(request, alert.alert_id)) body.removeAttribute("aria-busy");
    }
  }

  function invalidateEvidence() {
    state.evidenceRequest += 1;
    state.activeEvidence = null;
  }

  node("scan-button").addEventListener("click", scan);
  node("preferences-form").addEventListener("submit", savePreferences);
  node("notifications-enabled").addEventListener("change", preferencesChanged);
  node("minimum-severity").addEventListener("change", preferencesChanged);
  node("scan-interval").addEventListener("change", preferencesChanged);
  node("test-notification").addEventListener("click", testNotification);
  node("search-input").addEventListener("input", () => { renderEvents(); renderAlerts(); });
  node("event-kind-filter").addEventListener("change", renderEvents);
  node("severity-filter").addEventListener("change", renderAlerts);
  node("close-evidence").addEventListener("click", () => { invalidateEvidence(); node("evidence-dialog").close(); });
  node("evidence-dialog").addEventListener("cancel", invalidateEvidence);
  node("evidence-dialog").addEventListener("close", () => {
    if (node("evidence-dialog").open) return;
    invalidateEvidence();
    const target = [...node("alert-list").querySelectorAll("button")].find((button) => button.dataset.alertId === state.evidenceReturnId);
    (target || node("alerts-title")).focus();
  });
  document.addEventListener("visibilitychange", () => { if (!document.hidden) refresh(); });
  refresh();
  window.setInterval(() => { if (!document.hidden && !state.scanning) refresh(); }, 5000);
})();
