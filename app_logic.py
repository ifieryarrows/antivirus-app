import argparse
import os
import threading
import time
import json
from pathlib import Path
# Artik os, time ve diger scanner/utils importlarina burada ihtiyac yok,
# scanner_engine.py bunlari hallediyor.
from scanner_engine import scan_single_file, get_file_hash, check_against_local_db, check_entropy_heuristic
from scanner_engine import analyze_vt_scan_results, get_file_report, scan_file_with_vt, get_analysis_report, simplify_vt_report
from scanner_engine import load_local_malware_hashes

class AppLogic:
    def __init__(self, status_callback=None, progress_callback=None, results_callback=None, 
                 vt_api_key_missing_callback=None, scan_complete_callback=None):
        self.status_callback = status_callback
        self.progress_callback = progress_callback
        self.results_callback = results_callback
        self.vt_api_key_missing_callback = vt_api_key_missing_callback
        self.scan_complete_callback = scan_complete_callback
        
        self.cancel_flag = False
        self.scan_running = False
        
        # VirusTotal API anahtarını yükle
        self.vt_api_key = self._load_vt_api_key()
        
        # Yerel veritabanını yükle
        load_local_malware_hashes()
    
    def _load_vt_api_key(self):
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
                    return config.get("vt_api_key", "")
            except Exception:
                return ""
        return ""
    
    def _save_vt_api_key(self, api_key):
        """
        VirusTotal API anahtarını kaydeder. Öncelikle .env dosyasına kaydetmeyi dener,
        eğer .env dosyası yoksa config.json dosyasına kaydeder.
        """
        try:
            # .env dosyasına kaydetmeyi dene
            from dotenv import load_dotenv, set_key
            env_path = Path('.') / '.env'
            
            if env_path.exists():
                # .env dosyası varsa, API anahtarını güncelle
                set_key(dotenv_path=str(env_path), key_to_set="VT_API_KEY", value_to_set=api_key)
                return True
            else:
                # .env dosyası yoksa, yeni bir .env dosyası oluştur
                with open(env_path, 'w') as f:
                    f.write(f"VT_API_KEY={api_key}\n")
                return True
        except ImportError:
            # python-dotenv kütüphanesi yoksa, config.json'a kaydet
            config_file = "config.json"
            config = {}
            
            # Mevcut config'i yükle
            if os.path.exists(config_file):
                try:
                    with open(config_file, "r") as f:
                        config = json.load(f)
                except Exception:
                    pass
            
            # API anahtarını güncelle
            config["vt_api_key"] = api_key
            
            # Config'i kaydet
            try:
                with open(config_file, "w") as f:
                    json.dump(config, f, indent=4)
                return True
            except Exception:
                return False
    
    def get_vt_api_key(self):
        """VirusTotal API anahtarını döndürür."""
        return self.vt_api_key
    
    def set_vt_api_key(self, api_key):
        """VirusTotal API anahtarını ayarlar ve kaydeder."""
        self.vt_api_key = api_key
        return self._save_vt_api_key(api_key)
    
    def reset_cancel_scan_flag(self):
        """Tarama iptal bayrağını sıfırlar."""
        self.cancel_flag = False
    
    def cancel_scan(self):
        """Devam eden taramayı iptal eder."""
        self.cancel_flag = True
    
    def is_scan_running(self):
        """Tarama çalışıyor mu kontrolü."""
        return self.scan_running
    
    def _update_status(self, message):
        """Durum mesajını günceller."""
        if self.status_callback:
            self.status_callback(message)
    
    def _update_progress(self, value):
        """İlerleme çubuğunu günceller."""
        if self.progress_callback:
            self.progress_callback(value)
    
    def _add_result(self, message):
        """Sonuç listesine yeni bir sonuç ekler."""
        if self.results_callback:
            self.results_callback(message)
    
    def _scan_directory(self, directory_path, scan_type):
        """Bir dizindeki tüm dosyaları tarar."""
        total_files = 0
        scanned_files = 0
        
        # Dizindeki dosya sayısını hesapla (ilerleme çubuğu için)
        for root, _, files in os.walk(directory_path):
            total_files += len(files)
        
        if total_files == 0:
            self._update_status("Dizin boş veya erişilemiyor.")
            return
        
        # Her dosyayı tara
        for root, _, files in os.walk(directory_path):
            for file in files:
                if self.cancel_flag:
                    self._update_status("Tarama iptal edildi.")
                    return
                
                file_path = os.path.join(root, file)
                self._scan_file(file_path, scan_type)
                
                scanned_files += 1
                progress = int((scanned_files / total_files) * 100)
                self._update_progress(progress)
                self._update_status(f"Taranan: {scanned_files}/{total_files} - {os.path.basename(file_path)}")
        
        self._update_status(f"Tarama tamamlandı. {scanned_files} dosya tarandı.")
    
    def _scan_file(self, file_path, scan_type):
        """Tek bir dosyayı tarar."""
        try:
            if scan_type == "local":
                # Yerel tarama
                file_hash = get_file_hash(file_path)
                if not file_hash:
                    self._add_result(f"File: {file_path} - Status: Hata - Details: Hash hesaplanamadı.")
                    return
                
                # Yerel veritabanında kontrol
                if check_against_local_db(file_hash):
                    self._add_result(f"File: {file_path} - Status: Infected - Details: Yerel veritabanında zararlı olarak bulundu.")
                    return
                
                # Entropi kontrolü
                is_suspicious, entropy_value = check_entropy_heuristic(file_path)
                if is_suspicious:
                    self._add_result(f"File: {file_path} - Status: Suspicious - Details: Yüksek entropi ({entropy_value:.2f}).")
                    return
                
                self._add_result(f"File: {file_path} - Status: Clean - Details: Yerel taramada tehdit bulunamadı.")
                
            elif scan_type == "virustotal":
                # VirusTotal taraması
                if not self.vt_api_key:
                    if self.vt_api_key_missing_callback:
                        self.vt_api_key_missing_callback()
                    self._add_result(f"File: {file_path} - Status: Error - Details: VirusTotal API anahtarı bulunamadı.")
                    return
                
                self._add_result(f"File: {file_path} - Status: Scanning - Details: VirusTotal'a gönderiliyor...")
                
                # Önce hash ile sorgula
                file_hash = get_file_hash(file_path)
                vt_report = get_file_report(file_hash)
                
                if vt_report == "QuotaExceeded":
                    self._add_result(f"File: {file_path} - Status: Error - Details: VirusTotal API kotası aşıldı.")
                    return
                elif vt_report == "AuthError":
                    self._add_result(f"File: {file_path} - Status: Error - Details: VirusTotal API anahtarı geçersiz.")
                    return
                
                if vt_report:
                    # Rapor varsa analiz et
                    simplified_report = simplify_vt_report(vt_report)
                    decision, message = analyze_vt_scan_results(simplified_report)
                    self._add_result(f"File: {file_path} - Status: {decision.capitalize()} - Details: {message}")
                else:
                    # Rapor yoksa dosyayı yükle
                    self._add_result(f"File: {file_path} - Status: Scanning - Details: Dosya VirusTotal'a yükleniyor...")
                    analysis_id = scan_file_with_vt(file_path)
                    
                    if analysis_id == "QuotaExceeded":
                        self._add_result(f"File: {file_path} - Status: Error - Details: VirusTotal API kotası aşıldı (yükleme).")
                        return
                    elif analysis_id == "AuthError":
                        self._add_result(f"File: {file_path} - Status: Error - Details: VirusTotal API anahtarı geçersiz (yükleme).")
                        return
                    
                    if analysis_id:
                        # Analiz sonucunu bekle
                        self._add_result(f"File: {file_path} - Status: Waiting - Details: VirusTotal analizi bekleniyor...")
                        
                        # İlk bekleme
                        time.sleep(30)
                        analysis_report = get_analysis_report(analysis_id)
                        
                        # Analiz tamamlanmadıysa biraz daha bekle
                        if analysis_report and analysis_report not in ["QuotaExceeded", "AuthError"] and analysis_report.status != "completed":
                            time.sleep(30)
                            analysis_report = get_analysis_report(analysis_id)
                        
                        if analysis_report == "QuotaExceeded":
                            self._add_result(f"File: {file_path} - Status: Error - Details: VirusTotal API kotası aşıldı (analiz).")
                            return
                        elif analysis_report == "AuthError":
                            self._add_result(f"File: {file_path} - Status: Error - Details: VirusTotal API anahtarı geçersiz (analiz).")
                            return
                        
                        if analysis_report and analysis_report.status == "completed":
                            simplified_report = simplify_vt_report(analysis_report)
                            decision, message = analyze_vt_scan_results(simplified_report)
                            self._add_result(f"File: {file_path} - Status: {decision.capitalize()} - Details: {message}")
                        else:
                            self._add_result(f"File: {file_path} - Status: Pending - Details: VirusTotal analizi henüz tamamlanmadı.")
                    else:
                        self._add_result(f"File: {file_path} - Status: Error - Details: VirusTotal'a dosya yüklenemedi.")
            
        except Exception as e:
            self._add_result(f"File: {file_path} - Status: Error - Details: {str(e)}")
    
    def start_scan(self, path, scan_type):
        """Tarama işlemini başlatır."""
        self.scan_running = True
        self.cancel_flag = False
        
        try:
            if os.path.isdir(path):
                self._update_status(f"Dizin taranıyor: {path}")
                self._scan_directory(path, scan_type)
            elif os.path.isfile(path):
                self._update_status(f"Dosya taranıyor: {path}")
                self._update_progress(0)
                self._scan_file(path, scan_type)
                self._update_progress(100)
                self._update_status(f"Tarama tamamlandı: {os.path.basename(path)}")
            else:
                self._update_status(f"Hata: '{path}' bulunamadı.")
        except Exception as e:
            self._update_status(f"Tarama sırasında hata oluştu: {str(e)}")
        
        self.scan_running = False
        if self.scan_complete_callback:
            self.scan_complete_callback()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Basit bir dosya tarama programı.")
    parser.add_argument("file", help="Taranacak dosyanın yolu.")
    parser.add_argument("--force-vt", action="store_true", help="Dosyayı VirusTotal'a raporu olsa bile yeniden yükle.")
    parser.add_argument("--no-vt", action="store_true", help="VirusTotal taramasını devre dışı bırak.")
    parser.add_argument("--no-local", action="store_true", help="Yerel hash veritabanı taramasını devre dışı bırak.")
    parser.add_argument("--no-entropy", action="store_true", help="Entropi sezgisel taramasını devre dışı bırak.")
    
    args = parser.parse_args()

    enable_vt = not args.no_vt
    enable_local = not args.no_local
    enable_entropy = not args.no_entropy

    # scan_single_file artık scanner_engine'den geliyor
    scan_single_file(args.file, 
                     force_vt_upload=args.force_vt,
                     enable_vt_scan=enable_vt,
                     enable_local_scan=enable_local,
                     enable_entropy_scan=enable_entropy
                     )
