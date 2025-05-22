# Modern Antivirüs Uygulaması

Bu uygulama, yerel ve VirusTotal tabanlı tarama yetenekleri sunan bir antivirüs uygulamasıdır.

## Özellikler

- Yerel dosya taraması (hash tabanlı)
- Entropi analizi ile şüpheli dosya tespiti
- VirusTotal API entegrasyonu
- Kullanıcı dostu grafik arayüzü
- Açık/koyu tema desteği

## Kurulum

1. Gereksinimleri yükleyin:
   ```
   pip install -r requirements.txt
   ```

2. VirusTotal API anahtarınızı ayarlayın:
   - `.env` dosyası oluşturun ve içine şunu yazın:
     ```
     VT_API_KEY=your_api_key_here
     ```
   - Veya ortam değişkeni olarak ayarlayın:
     ```
     export VT_API_KEY=your_api_key_here  # Linux/Mac
     set VT_API_KEY=your_api_key_here     # Windows
     ```
   - Veya uygulama içinden "Ayarlar > VirusTotal API Anahtarı..." menüsünden ekleyin.

## Kullanım

Uygulamayı başlatmak için:
```
python gui_app.py
```

1. Tarama Türünü Seçin:
   - Yerel Tarama: Bilgisayarınızdaki dosyaları yerel imza veritabanı ile tarar.
   - VirusTotal Dosya Taraması: Seçilen dosyayı VirusTotal servisine göndererek tarar.

2. Dosya veya Dizin Seçin:
   - "Dosya Seç" butonu ile tek bir dosya seçin.
   - "Dizin Seç" butonu ile bir klasördeki tüm dosyaları taramak için klasör seçin.

3. Taramayı Başlatın:
   - "Taramayı Başlat" butonuna tıklayın.

4. Sonuçları İnceleyin:
   - Tarama durumu ve ilerlemesi "Durum" bölümünde gösterilir.
   - Detaylı sonuçlar "Tarama Sonuçları" listesinde görüntülenir.

## Geliştirici Notları

- Yerel veritabanı: `malware_hashes.txt` dosyasında saklanır.
- Tema değiştirme: Aydınlık/karanlık mod arasında geçiş yapabilirsiniz.
- API Anahtarı: VirusTotal API anahtarınızı güvenli bir şekilde saklayın, GitHub'a yüklerken `.env` ve `config.json` dosyalarını dahil etmeyin. 