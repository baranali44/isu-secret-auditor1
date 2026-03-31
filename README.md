# 🛡️ ISU Secret Auditor (Entropy-Based String Extractor)

Bu proje, İstinye Üniversitesi siber güvenlik vizyonu kapsamında geliştirilmiş, "Senaryo 8: String Çıkarıcı" hedeflerine uygun, gelişmiş bir açık kaynak güvenlik aracıdır. Kaynak kodlar ve binary dosyalar içerisindeki gizli parolaları (Hardcoded Secrets) statik analiz ve **Shannon Entropisi** yöntemleriyle tespit eder.

## 📌 Proje Güvenlik Analizi ve Mimari Raporu (5 Temel Aşama)

### Adım 1: Kurulum ve Kaynak Analizi
Proje saf Python ile yazılmıştır. Herhangi bir `curl | bash` körleme kurulumuna veya `sudo` (root) yetkisine ihtiyaç duymaz. Tedarik zinciri güvenliği (Supply Chain Security) prensiplerine uygun olarak, dışarıdan şüpheli bir kütüphane indirmez. Kullanıcı aracı izole bir ortamda, düşük yetkili bir kullanıcıyla doğrudan çalıştırabilir.

### Adım 2: Adli Bilişim (Forensics) ve Temizlik İzolasyonu
Araç tamamen statik bir analizcidir (Stateless). Çalıştığında sistemde herhangi bir arka plan servisi (daemon) bırakmaz, port açmaz ve dış ağa (C2 sunucularına vb.) bağlantı kurmaz. Analiz bittiğinde arkasında hiçbir log veya kalıntı dosya bırakmadığı için adli bilişim açısından sistem bütünlüğünü bozmaz. İz bırakmadan temizlenmesi için scriptin silinmesi yeterlidir.

### Adım 3: İş Akışları ve CI/CD (Pipeline) Analizi
Modern DevSecOps süreçlerine tam uyumludur. GitHub Actions üzerindeki Webhook mekanizmalarıyla tetiklenebilir. `--json` parametresi sayesinde CI/CD sunucuları (Jenkins, GitHub Actions) bu aracın çıktısını okuyabilir. Eğer araç yüksek entropili bir şifre bulursa, CI/CD pipeline'ı otomatik olarak kırılabilir (Fail-on-Severity).

### Adım 4: Docker Mimarisi ve Konteyner Güvenliği
Bu araç, Host işletim sisteminin kernel'ını riske atmadan, minimal bir `Alpine Linux` Docker konteyneri içerisine yerleştirilerek izole bir Sandbox ortamında çalıştırılabilir. Analiz edilen zararlı veya şüpheli dosyalar konteyner içinde kalsa bile "Container Breakout" zafiyetlerine karşı korunmuş olur.

### Adım 5: Tehdit Modelleme (Threat Modeling) ve Kaynak Kod
Hackerlar, sisteme sızmak için genellikle kaynak koda gömülmüş (Hardcoded) `API_KEY` veya şifreleri ararlar. Bu araç, basit RegEx kurallarını aşan "Shannon Entropisi" matematiksel modelini kullanarak, şifrelenmiş veya karmaşıklaştırılmış (obfuscated) dizgileri saldırganlardan önce tespit eder ve yetki yükseltme (Privilege Escalation) riskini kaynağında yok eder.

---
**Geliştirici:** Ali Baran Berktaş
