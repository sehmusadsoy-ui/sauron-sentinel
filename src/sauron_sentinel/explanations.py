"""Versioned Turkish guidance for bundled heuristics, separate from raw evidence.

These descriptions explain the shipped rule definitions, not confirmed incidents.
Unknown IDs deliberately receive no invented conditions or sensor capabilities.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType

EXPLANATION_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class _Explanation:
    summary: str
    why: str
    benign_causes: tuple[str, ...]
    checks: tuple[str, ...]


_CATALOG = MappingProxyType(
    {
        "auth-failure-burst": _Explanation(
            "Kısa sürede birden fazla başarısız kimlik doğrulama kaydı eşleşti. "
            "Bu eşleşme tek başına saldırı kanıtı değildir.",
            "auth.failure türünde, aynı cihaz ve kullanıcı için 60 saniyelik "
            "pencerede en az 5 kayıt eşleşti. Bildirimler arasında 60 saniyelik "
            "bekleme uygulanır.",
            (
                "Yanlış yazılan veya yeni değiştirilen bir parola.",
                "Eski parolayı kullanmaya devam eden bir uygulama ya da zamanlanmış görev.",
            ),
            (
                "Kanıt kayıtlarındaki kullanıcıyı ve zamanları kendi oturum açma denemelerinizle karşılaştırın.",
                "Windows Olay Görüntüleyicisi'nde ilgili kayıtların ayrıntılarını okuyun.",
            ),
        ),
        "rf-activity-burst": _Explanation(
            "Örnek RF verilerinde güçlü sinyal gözlemleri eşleşti. "
            "Canlı Windows izleyicisi RF veya CSI ölçümü yapmaz; bu eşleşme "
            "bir dinleme cihazı ya da saldırı tespiti değildir.",
            "rf.observation türünde, aynı cihaz için 10 saniyede en az 3 kayıt "
            "ve her kayıtta attributes.rssi_dbm >= -40 koşulu eşleşti. "
            "RSSI alanı sayısal olmalıdır. "
            "Bildirimler arasında 30 saniyelik bekleme uygulanır.",
            (
                "Yakındaki normal kablosuz cihazların örnek veya içe aktarılmış gözlemleri.",
                "Ölçüm yerinin, uzaklığının veya örnek veri üretiminin değişmesi.",
            ),
            (
                "Verinin kaynağını, sentetik işaretini, zamanlarını ve ölçüm koşullarını okuyun.",
                "Bu örnek eşleşmeden fiziksel bir cihazın varlığı veya amacı sonucunu çıkarmayın.",
            ),
        ),
        "motion-without-maintenance": _Explanation(
            "Örnek hareket göstergesi, bakım alanı kapalı olan bir kayıtta eşleşti. "
            "Canlı Windows izleyicisi hareket veya CSI sensörü değildir; eşleşme "
            "izinsiz bir kişinin bulunduğunu doğrulamaz.",
            "motion.observation türünde attributes.motion_score >= 0.8 ve "
            "attributes.maintenance = false olan tek bir kayıt yeterlidir. "
            "Hareket puanı sayısal, bakım alanı mantıksal olmalıdır. "
            "Aynı cihaz için pencere 30, bildirimler arası bekleme 60 saniyedir.",
            (
                "Normal hareketin yer aldığı örnek veya içe aktarılmış veri.",
                "Bakım alanının gerçeği yansıtmaması veya ölçüm gürültüsü.",
            ),
            (
                "Veri kaynağını, sentetik işaretini ve bakım alanının nasıl üretildiğini okuyun.",
                "Yalnız bu puana dayanarak fiziksel güvenlik kararı vermeyin.",
            ),
        ),
        "windows-service-installed": _Explanation(
            "Windows bir hizmet kurulumunu kaydetti. Hizmet kurulumu normal "
            "bir yazılım işlemi olabilir; bu kayıt kötü niyeti doğrulamaz.",
            "service.installed türündeki tek bir kayıt eşleşir. Bu kural "
            "hizmet adını, dosya yolunu veya dijital imzayı değerlendirmez.",
            (
                "Yazılım, sürücü, güncelleme veya güvenlik aracı kurulumu.",
                "Yetkili bir yöneticinin bakım veya kurumsal dağıtım işlemi.",
            ),
            (
                "Kanıttaki zamanı, hizmet adını ve varsa dosya yolunu son kurulumlarınızla karşılaştırın.",
                "Hizmet özelliklerini ve dosyanın yayıncı bilgisini salt okunur biçimde inceleyin.",
            ),
        ),
        "windows-log-cleared": _Explanation(
            "Windows olay günlüğünün temizlendiğini bildiren bir kayıt eşleşti. "
            "Kayıt tek başına iz gizleme veya saldırı kanıtı değildir.",
            "log.cleared türündeki tek bir kayıt eşleşir. Temizleme işleminin "
            "yetkili olup olmadığı bu kural tarafından belirlenmez.",
            (
                "Yetkili bakım, sorun giderme veya günlük yönetimi işlemi.",
                "Bir yönetim aracının planlanmış günlük temizliği.",
            ),
            (
                "Kanıttaki günlük adını, zamanı ve varsa kullanıcı bilgisini inceleyin.",
                "Bu zamanı bilinen bakım kayıtlarıyla karşılaştırın; kalan günlükleri temizlemeyin.",
            ),
        ),
        "windows-defender-threat": _Explanation(
            "Microsoft Defender'ın tehdit algılama kaydı eşleşti. Bu kayıt "
            "tek başına etkin bulaşmayı veya saldırının başarılı olduğunu doğrulamaz.",
            "defender.threat türündeki tek bir kayıt eşleşir. Bu kural "
            "Defender'ın sonraki eyleminin sonucunu veya mevcut durumu doğrulamaz.",
            (
                "Yanlış pozitif olabilecek bir dosya veya bilinen bir test dosyası.",
                "Defender'ın zaten engellediği veya karantinaya aldığı bir öğe.",
            ),
            (
                "Windows Güvenliği'ndeki Koruma geçmişini açıp öğeyi ve uygulanan eylemi okuyun.",
                "Dosyayı çalıştırmadan, algılama zamanı ve yayıncı bilgisini bilinen işlemlerle karşılaştırın.",
            ),
        ),
        "windows-defender-disabled": _Explanation(
            "Microsoft Defender korumasının devre dışı bırakılmasına ilişkin bir "
            "kayıt eşleşti. Geçmişteki bu kayıt korumanın şu anda kapalı olduğunu doğrulamaz.",
            "defender.disabled türündeki tek bir kayıt eşleşir. Bu kural "
            "değişikliğin nedenini, süresini veya mevcut koruma durumunu belirlemez.",
            (
                "Yetkili bakım veya başka bir güvenlik ürününe geçiş.",
                "Kurumsal ilke ya da yönetici tarafından yapılmış bir değişiklik.",
            ),
            (
                "Windows Güvenliği'nde mevcut koruma durumunu salt okunur biçimde kontrol edin.",
                "Kayıt zamanını yetkili bakım ve kurum ilkesi bilgileriyle karşılaştırın.",
            ),
        ),
        "windows-account-created": _Explanation(
            "Windows bir kullanıcı hesabı oluşturulduğunu kaydetti. "
            "Bu kayıt hesabın yetkisiz oluşturulduğunu göstermez.",
            "account.created türündeki tek bir kayıt eşleşir. Hesabın amacı "
            "veya oluşturma işleminin yetkisi bu kuralda değerlendirilmez.",
            (
                "Yeni kullanıcı, uygulama veya hizmet için hesap hazırlanması.",
                "Yetkili kurulum ya da kurumsal hesap yönetimi işlemi.",
            ),
            (
                "Kanıttaki hesap adını ve oluşturma zamanını bilinen kurulumlarla karşılaştırın.",
                "Hesap özelliklerini ve varsa kayıttaki işlemi yapan kullanıcıyı okuyun.",
            ),
        ),
        "windows-group-member-added": _Explanation(
            "Windows bir yerel güvenlik grubuna üye eklendiğini kaydetti. "
            "Her grup değişikliği yönetici yetkisi artışı veya saldırı anlamına gelmez.",
            "group.member_added türündeki tek bir kayıt eşleşir. Bu kural "
            "grubun ayrıcalık düzeyini veya işlemin yetkisini değerlendirmez.",
            (
                "Yetkili kullanıcı erişimi, uygulama kurulumu veya yönetim değişikliği.",
                "Kurumsal ilkelerin yerel gruplara uygulanması.",
            ),
            (
                "Kanıttaki grup ve üye bilgilerini okuyup beklenen erişimle karşılaştırın.",
                "Grubun mevcut üyelerini ve değişiklik zamanındaki bakım bilgisini salt okunur inceleyin.",
            ),
        ),
        "windows-unexpected-shutdown": _Explanation(
            "Windows beklenmeyen bir kapanma veya yeniden başlatma kaydetti. "
            "Bu kayıt tek başına güvenlik ihlali kanıtı değildir.",
            "system.unexpected_shutdown türündeki tek bir kayıt eşleşir. "
            "Bu kural kapanmanın teknik nedenini belirlemez.",
            (
                "Elektrik kesintisi, pilin bitmesi veya güç düğmesiyle zorla kapatma.",
                "Sistem çökmesi, sürücü sorunu veya donanım hatası.",
            ),
            (
                "Kayıt zamanını bildiğiniz güç kesintileri ve yeniden başlatmalarla karşılaştırın.",
                "Güvenilirlik Geçmişi ve Olay Görüntüleyicisi'nde aynı zamandaki kayıtları okuyun.",
            ),
        ),
    }
)

_UNKNOWN = _Explanation(
    "Bu kural için katalogda açıklama bulunmuyor. Eşleşme tek başına "
    "doğrulanmış bir saldırı anlamına gelmez.",
    "Kural kimliği biliniyor ancak koşulları bu katalogda tanımlı değil. "
    "Gerçek eşleşme koşulları için kullanılan kural tanımını inceleyin.",
    ("Olası normal nedenler bu kural için bilinmiyor; kanıt ve bağlam gereklidir.",),
    (
        "Ham uyarıdaki kural kimliğini, eşleşme sayısını, zamanı ve kanıt kayıtlarını okuyun.",
        "Kural tanımını ve bilinen bakım işlemlerini salt okunur biçimde karşılaştırın.",
    ),
)


def explanation_for(rule_id: str) -> dict:
    """Return a fresh JSON-ready description without touching the supplied evidence."""
    item = _CATALOG.get(rule_id, _UNKNOWN)
    return {
        "schema_version": EXPLANATION_SCHEMA_VERSION,
        "rule_id": rule_id,
        "summary": item.summary,
        "why": item.why,
        "benign_causes": list(item.benign_causes),
        "checks": list(item.checks),
    }
