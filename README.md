# Modern Antivirüs Uygulaması

Bu uygulama, hem yerel hem de bulut tabanlı (VirusTotal) tarama yetenekleri sunan güçlü bir antivirüs çözümüdür. Kullanıcı dostu grafik arayüzü ile sistemlerindeki potansiyel tehditleri belirlemelerine ve azaltmalarına yardımcı olmak için tasarlanmıştır.

### Özellikler

* **Yerel Dosya Taraması**: Yerel bir kötü amaçlı yazılım imza veritabanına (`malware_hashes.txt`) karşı hash tabanlı bir algılama yöntemi kullanır (geliştirme aşamasında).
* **Entropi Analizi**: Şüpheli veya paketlenmiş yürütülebilir dosyaları tanımlamak için dosya entropisine dayalı sezgisel bir tarama uygular.
* **VirusTotal API Entegrasyonu**: Çok sayıda antivirüs motorundan içgörüler sağlayarak kapsamlı dosya analizi için VirusTotal API'sini kullanır.
* **Karantina İşlevselliği**: Algılanan kötü amaçlı dosyaları daha fazla zarar görmesini önlemek için belirlenmiş bir karantina dizinine güvenli bir şekilde taşır.
* **Kullanıcı Dostu Grafik Arayüz (GUI)**: Sezgisel bir kullanıcı deneyimi için Tkinter ve ttkthemes ile oluşturulmuştur.
* **Tema Desteği**: Kullanıcı tercihine göre hem aydınlık hem de karanlık mod temaları sunar.
* **Esnek API Anahtarı Yönetimi**: VirusTotal API anahtarlarını ortam değişkenlerinden, `.env` dosyalarından veya bir `config.json` dosyasından yüklemeyi destekler, ayrıca uygulama içi yapılandırma seçeneği de bulunur.
* **Gerçek Zamanlı Durum ve İlerleme**: GUI aracılığıyla tarama durumu ve ilerlemesi hakkında güncellemeler sağlar.
* **Detaylı Tarama Sonuçları**: Dosya yolu, durumu (Virüslü, Temiz, Şüpheli, Hata) ve belirli ayrıntılar dahil olmak üzere kapsamlı tarama sonuçlarını görüntüler.

### Kurulum

Uygulamayı kurmak ve çalıştırmak için şu adımları izleyin:

1.  **Depoyu Klonlayın**:
    ```bash
    git clone <repository_url>
    cd antivirus-app
    ```

2.  **Gereksinimleri Yükleyin**:
    Python'ın yüklü olduğundan emin olun (3.7+ önerilir). Ardından gerekli kütüphaneleri yükleyin:
    ```bash
    pip install -r requirements.txt
    ```
    Başlıca bağımlılıklar arasında VirusTotal entegrasyonu için `vt-py`, ikonlar için `Pillow`, geliştirilmiş GUI temaları için `ttkthemes` ve ortam değişkeni yönetimi için `python-dotenv` bulunur.

3.  **VirusTotal API Anahtarını Yapılandırın**:
    VirusTotal tarama özellikleri için bir VirusTotal API anahtarı gereklidir. Bunu aşağıdaki yollardan biriyle ayarlayabilirsiniz:
    * **Ortam Değişkeni**:
        ```bash
        export VT_API_KEY=api_anahtarınız_buraya  # Linux/macOS
        set VT_API_KEY=api_anahtarınız_buraya     # Windows
        ```
    * **`.env` dosyası**: Uygulamanın kök dizininde `.env` adında bir dosya oluşturun ve içine şunu ekleyin:
        ```
        VT_API_KEY=api_anahtarınız_buraya
        ```
    * **`config.json` dosyası**: Kök dizinde bir `config.json` dosyası oluşturun ve içine şunu ekleyin:
        ```json
        {
            "vt_api_key": "api_anahtarınız_buraya"
        }
        ```
    * **Uygulama İçi Ayar**: Uygulamanın menü çubuğundan `Ayarlar > VirusTotal API Anahtarı...` seçeneğine gidin ve anahtarınızı girin.

### Kullanım

1.  **Tarama Türünü Seçin**:
    * **Yerel Tarama**: Bilgisayarınızdaki dosyaları yerel imza veritabanına göre tarar ve entropi analizi yapar.
    * **VirusTotal Dosya Taraması**: Seçilen dosyayı daha ayrıntılı bir analiz için VirusTotal hizmetine gönderir. Bu, aktif bir internet bağlantısı ve yapılandırılmış bir VirusTotal API anahtarı gerektirir.

2.  **Dosya veya Dizin Seçin**:
    * Tek bir dosya seçmek için "Dosya Seç" düğmesine tıklayın.
    * Tam bir dizin taraması için bir klasör seçmek üzere "Dizin Seç" düğmesine tıklayın.

3.  **Taramayı Başlatın**:
    Tarama işlemini başlatmak için "Taramayı Başlat" düğmesine tıklayın.

4.  **Sonuçları İnceleyin**:
    * "Durum" bölümü mevcut tarama durumunu ve ilerlemesini gösterecektir.
    * Dosya yolu, durumu ve belirli ayrıntılarla birlikte ayrıntılı sonuçlar "Tarama Sonuçları" listesinde görüntülenecektir. Kötü amaçlı veya şüpheli olarak tanımlanan dosyalar vurgulanacaktır.

### Geliştirici Notları

* **Yerel Veritabanı**: `malware_hashes.txt` dosyası bilinen kötü amaçlı yazılım hash değerlerini içerir. Bu dosyayı yeni SHA256 hash'leriyle güncelleyebilirsiniz.
* **Temalar**: Uygulama, GUI aracılığıyla aydınlık ve karanlık mod arasında geçişi destekler.
* **API Anahtarı Güvenliği**: VirusTotal API anahtarınızı daima güvenli bir şekilde saklayın. API anahtarınızı içeren `.env` veya `config.json` dosyalarını genel depolara göndermeyin.
* **Karantina Dizini**: Algılanan kötü amaçlı dosyalar, uygulamanın kök dizinindeki `quarantined` adlı bir dizine taşınır.
* **Tarama Mantığı**: `scanner_engine.py` modülü farklı tarama yöntemlerini (yerel hash, entropi ve VirusTotal) düzenler. `app_logic.py` ise GUI ile tarama motoru arasında bir köprü sağlar.
* **Asenkron İşlemler**: VirusTotal API etkileşimleri, GUI'nin donmasını önlemek için asenkron olarak ele alınır ve Tkinter'in ana döngüsü için senkron bir sarmalayıcı bulunur.
