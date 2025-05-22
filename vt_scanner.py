# antivirus_projesi/vt_scanner.py

import vt
import os
import time
import asyncio
import json
from pathlib import Path

# API anahtarını yükleme fonksiyonu
def load_api_key():
    """
    API anahtarını çeşitli kaynaklardan yüklemeye çalışır:
    1. Ortam değişkeni (VT_API_KEY)
    2. .env dosyası (python-dotenv kütüphanesi varsa)
    3. config.json dosyası
    """
    # 1. Ortam değişkeninden yükleme
    api_key = os.environ.get('VT_API_KEY')
    if api_key:
        return api_key
    
    # 2. .env dosyasından yükleme (python-dotenv kütüphanesi varsa)
    try:
        from dotenv import load_dotenv
        env_path = Path('.') / '.env'
        if env_path.exists():
            load_dotenv()
            api_key = os.environ.get('VT_API_KEY')
            if api_key:
                return api_key
    except ImportError:
        pass  # python-dotenv kütüphanesi yüklü değil
    
    # 3. config.json dosyasından yükleme
    config_file = "config.json"
    if os.path.exists(config_file):
        try:
            with open(config_file, "r") as f:
                config = json.load(f)
                api_key = config.get("vt_api_key")
                if api_key and isinstance(api_key, str) and len(api_key) > 0:
                    return api_key
                else:
                    print("config.json dosyasında API anahtarı bulunamadı veya geçersiz.")
        except Exception as e:
            print(f"config.json dosyası okunurken hata: {e}")
    
    return None

# API anahtarını yükle
API_KEY = load_api_key()

if not API_KEY:
    print("UYARI: VirusTotal API anahtarı bulunamadı. Lütfen aşağıdaki yöntemlerden biriyle API anahtarınızı ayarlayın:")
    print("1. Ortam değişkeni olarak: VT_API_KEY=your_api_key")
    print("2. .env dosyası oluşturun: VT_API_KEY=your_api_key")
    print("3. config.json dosyası oluşturun: {\"vt_api_key\": \"your_api_key\"}")

# Asenkron client ve senkronizasyon mekanizmaları
class VirusTotalScanner:
    def __init__(self, api_key):
        self.api_key = api_key
        self.client = None
        self._loop = None
    
    def __enter__(self):
        if self.client is None:
            self.client = vt.Client(self.api_key)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.client:
            self.client.close()
            self.client = None
    
    async def get_file_report_async(self, file_hash):
        """
        Verilen hash değeri için VirusTotal'dan dosya raporunu asenkron olarak alır.
        """
        if not self.client:
            self.client = vt.Client(self.api_key)

        try:
            file_info = await self.client.get_object_async(f"/files/{file_hash}")
            return file_info
        except vt.APIError as e:
            if e.code == "NotFoundError":
                print(f"Dosya hash'i ({file_hash}) VirusTotal'da bulunamadı.")
                return None
            elif e.code == "QuotaExceededError":
                print("VirusTotal API kotası aşıldı. Bir süre sonra tekrar deneyin.")
                return "QuotaExceeded"
            elif e.code == "AuthenticationError":
                print("VirusTotal API anahtarı geçersiz veya yetkilendirme hatası.")
                return "AuthError"
            else:
                print(f"VirusTotal API Hatası (get_file_report - {file_hash}): {e.message} (Kod: {e.code})")
                return None
    
    async def scan_file_with_vt_async(self, file_path):
        """
        Bir dosyayı VirusTotal'a asenkron olarak yükler ve analiz ID'sini döndürür.
        """
        if not self.client:
            self.client = vt.Client(self.api_key)

        try:
            with open(file_path, "rb") as f:
                # wait_for_completion=False ile analizin bitmesini beklemiyoruz
                analysis = await self.client.scan_file_async(f)
                print(f"'{os.path.basename(file_path)}' VirusTotal'a yüklendi. Analiz ID: {analysis.id}")
                return analysis.id
        except FileNotFoundError:
            print(f"Hata: Dosya bulunamadı - {file_path}")
            return None
        except vt.APIError as e:
            if e.code == "QuotaExceededError":
                print("VirusTotal API kotası aşıldı. Dosya yüklenemedi.")
                return "QuotaExceeded"
            print(f"VirusTotal API Hatası (scan_file_with_vt - {file_path}): {e.message} (Kod: {e.code})")
            return None
        except Exception as e:
            print(f"Dosya yüklenirken beklenmedik bir hata oluştu ({file_path}): {e}")
            return None
    
    async def get_analysis_report_async(self, analysis_id):
        """
        Verilen analiz ID'si için VirusTotal'dan analiz raporunu asenkron olarak alır.
        """
        if not self.client:
            self.client = vt.Client(self.api_key)

        try:
            analysis_obj = await self.client.get_object_async(f"/analyses/{analysis_id}")
            if analysis_obj.status == "completed":
                return analysis_obj
            else:
                print(f"Analiz durumu: {analysis_obj.status}. Henüz tamamlanmadı.")
                return None
        except vt.APIError as e:
            if e.code == "QuotaExceededError":
                print("VirusTotal API kotası aşıldı. Analiz raporu alınamadı.")
                return "QuotaExceeded"
            print(f"VirusTotal API Hatası (get_analysis_report - {analysis_id}): {e.message} (Kod: {e.code})")
            return None
    
    def _get_or_create_event_loop(self):
        """Event loop alır veya gerekiyorsa yeni bir tane oluşturur."""
        try:
            # Mevcut loop'u al
            return asyncio.get_event_loop()
        except RuntimeError:
            # "There is no current event loop in thread" hatası için yeni loop oluştur
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            return loop
    
    def get_file_report(self, file_hash):
        """
        Asenkron fonksiyonu senkron çağrı olarak sarar (wrapper)
        """
        loop = self._get_or_create_event_loop()
        return loop.run_until_complete(self.get_file_report_async(file_hash))
    
    def scan_file_with_vt(self, file_path):
        """
        Asenkron fonksiyonu senkron çağrı olarak sarar (wrapper)
        """
        loop = self._get_or_create_event_loop()
        return loop.run_until_complete(self.scan_file_with_vt_async(file_path))
    
    def get_analysis_report(self, analysis_id):
        """
        Asenkron fonksiyonu senkron çağrı olarak sarar (wrapper)
        """
        loop = self._get_or_create_event_loop()
        return loop.run_until_complete(self.get_analysis_report_async(analysis_id))

# Singleton scanner instance oluştur
scanner = VirusTotalScanner(API_KEY)

def get_file_report(file_hash):
    """
    Verilen hash değeri için VirusTotal'dan dosya raporunu alır. (Senkron API)
    """
    with scanner:
        return scanner.get_file_report(file_hash)

def scan_file_with_vt(file_path):
    """
    Bir dosyayı VirusTotal'a yükler ve analiz ID'sini döndürür. (Senkron API)
    """
    with scanner:
        return scanner.scan_file_with_vt(file_path)

def get_analysis_report(analysis_id):
    """
    Verilen analiz ID'si için VirusTotal'dan analiz raporunu alır. (Senkron API)
    """
    with scanner:
        return scanner.get_analysis_report(analysis_id)

def simplify_vt_report(vt_object):
    """
    VirusTotal dosya veya analiz nesnesinden temel bilgileri çıkarır.
    """
    if not vt_object:
        return None

    report_summary = {}
    try:
        # Hem dosya objesi hem de analiz objesi için ortak olabilecek alanlar
        if hasattr(vt_object, 'last_analysis_stats'): # Dosya objesi
            stats = vt_object.last_analysis_stats
            report_summary['type'] = 'file_report'
            report_summary['id'] = vt_object.id # Bu dosyanın hash'i olacak
        elif hasattr(vt_object, 'stats'): # Analiz objesi
            stats = vt_object.stats
            report_summary['type'] = 'analysis_report'
            report_summary['id'] = vt_object.id # Bu analiz ID'si
            # Analiz objesinden dosya hash'ini de alabiliriz (meta altında)
            if hasattr(vt_object, 'meta') and 'file_info' in vt_object.meta:
                 report_summary['file_hash_md5'] = vt_object.meta['file_info'].get('md5')
                 report_summary['file_hash_sha256'] = vt_object.meta['file_info'].get('sha256')
        else:
            print("Rapor formatı tanınamadı.")
            return None

        report_summary['malicious'] = stats.get('malicious', 0)
        report_summary['suspicious'] = stats.get('suspicious', 0)
        report_summary['undetected'] = stats.get('undetected', 0)
        report_summary['harmless'] = stats.get('harmless', 0) # Bazen bu da olabilir
        report_summary['timeout'] = stats.get('timeout', 0)

        # Tespit eden motorların detayları (opsiyonel, çok uzun olabilir)
        # report_summary['results'] = {}
        # if hasattr(vt_object, 'last_analysis_results'): # Dosya objesi
        #     for engine, result in vt_object.last_analysis_results.items():
        #         report_summary['results'][engine] = result['category']
        # elif hasattr(vt_object, 'results'): # Analiz objesi
        #     for engine, result in vt_object.results.items():
        #        report_summary['results'][engine] = result['category']

        return report_summary
    except Exception as e:
        print(f"VirusTotal raporu işlenirken hata: {e}")
        return None

async def main_async():
    """Modül testleri için asenkron ana fonksiyon."""
    print("VirusTotal Tarayıcı Modülü Testi (Async)")

    test_safe_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f" # EICAR
    
    print(f"\n'{test_safe_hash}' için rapor alınıyor...")
    async with vt.Client(API_KEY) as client:
        try:
            file_info = await client.get_object_async(f"/files/{test_safe_hash}")
            simple_report = simplify_vt_report(file_info)
            print("Basitleştirilmiş Rapor:", simple_report)
        except Exception as e:
            print(f"Hata: {e}")

    test_file_to_upload = "test_vt_upload.txt"
    with open(test_file_to_upload, "w") as f:
        f.write("This is a test file for VirusTotal upload from vt-py.")
    
    print(f"\n'{test_file_to_upload}' dosyası VirusTotal'a yükleniyor...")
    with scanner:
        analysis_id = await scanner.scan_file_with_vt_async(test_file_to_upload)
    
    if analysis_id and analysis_id not in ["QuotaExceeded", "AuthError"]:
        print(f"Analiz ID: {analysis_id}. Rapor için birkaç saniye/dakika bekleniyor...")
        await asyncio.sleep(60)
        
        print(f"\nAnaliz raporu alınıyor (ID: {analysis_id})...")
        with scanner:
            analysis_result = await scanner.get_analysis_report_async(analysis_id)
        
        if analysis_result and analysis_result not in ["QuotaExceeded", "AuthError"]:
            simple_analysis_report = simplify_vt_report(analysis_result)
            print("Basitleştirilmiş Analiz Raporu:", simple_analysis_report)
        elif analysis_result == "QuotaExceeded":
            print("Test başarısız: Kota aşıldı.")
        else:
            print(f"Analiz raporu ({analysis_id}) alınamadı veya henüz tamamlanmadı.")
    
    elif analysis_id == "QuotaExceeded":
        print("Dosya yükleme testi başarısız: Kota aşıldı.")

    if os.path.exists(test_file_to_upload):
        os.remove(test_file_to_upload)

    print("\nTest tamamlandı.")

# Test için (Bu dosyayı doğrudan çalıştırdığınızda çalışır)
if __name__ == "__main__":
    # Asenkron test çalıştır
    asyncio.run(main_async())
    
    # Senkron API testleri
    print("\n=== Senkron API Testleri ===")
    test_safe_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    
    print(f"'{test_safe_hash}' için rapor alınıyor (senkron)...")
    report = get_file_report(test_safe_hash)
    if report and report not in ["QuotaExceeded", "AuthError"]:
        simple_report = simplify_vt_report(report)
        print("Basitleştirilmiş Senkron Rapor:", simple_report)