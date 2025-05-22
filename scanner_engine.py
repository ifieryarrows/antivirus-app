import os
import time
import hashlib # local_scanner'dan geldi
import math    # local_scanner'dan geldi
# from local_scanner import get_file_hash, check_against_local_db, check_entropy_heuristic # BU SATIR KALKACAK
from vt_scanner import get_file_report, scan_file_with_vt, get_analysis_report, simplify_vt_report
# from file_operations import quarantine_file # BU SATIR KALKACAK

# --- local_scanner.py'den taşınan kodlar ---
MALWARE_HASHES_FILE = "malware_hashes.txt"
LOCAL_MALWARE_HASHES = set()

def load_local_malware_hashes():
    global LOCAL_MALWARE_HASHES
    LOCAL_MALWARE_HASHES = set()
    if os.path.exists(MALWARE_HASHES_FILE):
        try:
            with open(MALWARE_HASHES_FILE, "r") as f:
                for line in f:
                    hash_val = line.strip()
                    if hash_val and not hash_val.startswith("#"):
                        LOCAL_MALWARE_HASHES.add(hash_val)
        except Exception as e:
            pass # GUI'de hataları sessizce geçebiliriz veya loglayabiliriz

def get_file_hash(filepath, algorithm="sha256", block_size=65536):
    hasher = hashlib.new(algorithm)
    try:
        with open(filepath, 'rb') as f:
            for block in iter(lambda: f.read(block_size), b''):
                hasher.update(block)
        return hasher.hexdigest()
    except IOError:
        return None
    except Exception:
        return None

def check_against_local_db(file_hash):
    if not LOCAL_MALWARE_HASHES: # İlk erişimde veya boşsa yükle
        load_local_malware_hashes()
    return file_hash in LOCAL_MALWARE_HASHES

def calculate_entropy(data_bytes):
    if not data_bytes:
        return 0
    entropy = 0
    len_data = len(data_bytes)
    byte_counts = [0] * 256
    for byte_val in data_bytes:
        byte_counts[byte_val] += 1
    for count in byte_counts:
        if count == 0:
            continue
        p_x = float(count) / len_data
        entropy -= p_x * math.log2(p_x)
    return entropy

def check_entropy_heuristic(filepath, threshold=7.0):
    try:
        with open(filepath, 'rb') as f:
            file_data = f.read()
        if not file_data:
            return False, 0.0
        entropy_value = calculate_entropy(file_data)
        is_suspicious = entropy_value > threshold
        return is_suspicious, entropy_value
    except IOError:
        return False, -1.0
    except Exception:
        return False, -1.0
# --- local_scanner.py'den taşınan kodlar BİTTİ ---

# --- file_operations.py (utils.py)'dan taşınan kodlar ---
QUARANTINE_DIR = "quarantined"

def ensure_quarantine_dir_exists():
    if not os.path.exists(QUARANTINE_DIR):
        try:
            os.makedirs(QUARANTINE_DIR)
        except OSError as e:
            return False
    return True

def quarantine_file(file_path):
    if not ensure_quarantine_dir_exists():
        return False
    if not os.path.exists(file_path):
        return False
    file_name = os.path.basename(file_path)
    destination = os.path.join(QUARANTINE_DIR, file_name)
    try:
        count = 1
        base, ext = os.path.splitext(destination)
        while os.path.exists(destination):
            destination = f"{base}_{count}{ext}"
            count += 1
        os.rename(file_path, destination)
        return True
    except Exception as e:
        return False
# --- file_operations.py (utils.py)'dan taşınan kodlar BİTTİ ---

# VirusTotal raporunda zararlı/şüpheli eşiği
VT_MALICIOUS_THRESHOLD = 1 # En az 1 motor zararlı bulursa
VT_SUSPICIOUS_THRESHOLD = 3 # En az 3 motor şüpheli/zararlı bulursa (malicious + suspicious)

# Entropi için şüpheli eşiği
ENTROPY_SUSPICIOUS_THRESHOLD = 7.2

def analyze_vt_scan_results(vt_simplified_report):
    """VirusTotal rapor özetini analiz eder ve kararı döndürür."""
    if not vt_simplified_report:
        return "error", "Rapor alınamadı veya işlenemedi."

    malicious_count = vt_simplified_report.get('malicious', 0)
    suspicious_count = vt_simplified_report.get('suspicious', 0)
    total_detections = malicious_count + suspicious_count

    if malicious_count >= VT_MALICIOUS_THRESHOLD:
        return "malicious", f"VirusTotal'da {malicious_count} motor tarafından ZARARLI olarak işaretlendi."
    elif total_detections >= VT_SUSPICIOUS_THRESHOLD:
        return "suspicious", f"VirusTotal'da {total_detections} motor tarafından ŞÜPHELİ/ZARARLI olarak işaretlendi."
    else:
        return "clean", f"VirusTotal'da {total_detections} motor tarafından tespit edildi (Eşiklerin altında)."

def scan_single_file(file_path, force_vt_upload=False, enable_vt_scan=True, enable_local_scan=True, enable_entropy_scan=True):
    """
    Tek bir dosyayı tarar.
    1. Yerel hash veritabanı
    2. Entropi analizi
    3. VirusTotal hash sorgusu
    4. Gerekirse VirusTotal yüklemesi
    """
    if not os.path.exists(file_path):
        print(f"Hata: Dosya bulunamadı - {file_path}")
        return

    print(f"\n--- '{os.path.basename(file_path)}' TARANIYOR ---")
    if enable_local_scan and not LOCAL_MALWARE_HASHES: # Emin olmak için kontrol
        load_local_malware_hashes()

    file_sha256 = get_file_hash(file_path, "sha256")
    if not file_sha256:
        print(f"'{file_path}' için hash hesaplanamadı. Tarama iptal edildi.")
        return

    print(f"SHA256: {file_sha256}")
    is_suspicious_locally = False
    local_scan_reason = ""

    # 1. Yerel Hash Veritabanı Kontrolü
    if enable_local_scan:
        if check_against_local_db(file_sha256):
            is_suspicious_locally = True
            local_scan_reason = "Yerel veritabanında zararlı olarak bulundu."
            print(f"DURUM: ZARARLI (Yerel DB) - {local_scan_reason}")
    
    # 2. Entropi Sezgisel Kontrolü
    if enable_entropy_scan and not is_suspicious_locally: # Henüz zararlı bulunmadıysa
        is_entropy_suspicious, entropy_value = check_entropy_heuristic(file_path, ENTROPY_SUSPICIOUS_THRESHOLD)
        print(f"Entropi Değeri: {entropy_value:.2f}")
        if is_entropy_suspicious:
            is_suspicious_locally = True # Sadece şüpheli olarak işaretle, VT'ye de soralım.
            local_scan_reason = f"Yüksek entropi ({entropy_value:.2f}) nedeniyle şüpheli."
            print(f"DURUM: ŞÜPHELİ (Yüksek Entropi) - {local_scan_reason}")

    # 3. VirusTotal Entegrasyonu
    if enable_vt_scan:
        print("\nVirusTotal ile kontrol ediliyor...")
        vt_report_data = None
        analysis_pending = False
        vt_decision = "unknown"
        vt_message = "VirusTotal taraması yapılamadı veya sonuç bekleniyor."

        if not force_vt_upload:
            print(f"'{file_sha256}' için VirusTotal raporu sorgulanıyor...")
            try:
                vt_report_object = get_file_report(file_sha256)
                
                if vt_report_object == "QuotaExceeded":
                    print("UYARI: VirusTotal API kotası aşıldı. VT taraması atlanıyor.")
                    vt_decision = "error"
                    vt_message = "Kota aşıldı."
                elif vt_report_object == "AuthError":
                    print("HATA: VirusTotal API anahtarı geçersiz. VT taraması atlanıyor.")
                    vt_decision = "error"
                    vt_message = "API Anahtarı Hatası."
                elif vt_report_object:
                    print("Mevcut VirusTotal raporu bulundu.")
                    vt_report_data = simplify_vt_report(vt_report_object)
                else:
                    print("VirusTotal'da mevcut rapor bulunamadı. Dosya yüklenecek.")
                    force_vt_upload = True # Rapor yoksa yüklemeyi zorunlu kıl
            except Exception as e:
                print(f"VirusTotal raporu alınırken hata oluştu: {str(e)}")
                vt_decision = "error"
                vt_message = f"API hatası: {str(e)}"

        if force_vt_upload and (not vt_report_data or vt_report_data.get('malicious',0) == 0): 
            print(f"'{os.path.basename(file_path)}' VirusTotal'a yeniden tarama için yükleniyor...")
            try:
                analysis_id = scan_file_with_vt(file_path)
                if analysis_id and analysis_id not in ["QuotaExceeded", "AuthError"]:
                    analysis_pending = True
                    print(f"Analiz ID: {analysis_id}. Sonuç için ~60-120 saniye bekleniyor...")
                    time.sleep(60) # İlk bekleme
                    
                    try:
                        vt_analysis_obj = get_analysis_report(analysis_id)
                        if not vt_analysis_obj or vt_analysis_obj.status != "completed":
                            print("Analiz henüz tamamlanmadı, 60 saniye daha bekleniyor...")
                            time.sleep(60)
                            vt_analysis_obj = get_analysis_report(analysis_id)

                        if vt_analysis_obj and vt_analysis_obj not in ["QuotaExceeded", "AuthError"]:
                            if vt_analysis_obj.status == "completed":
                                print("VirusTotal analizi tamamlandı.")
                                vt_report_data = simplify_vt_report(vt_analysis_obj)
                            else:
                                print(f"VirusTotal analizi hala tamamlanmadı (Durum: {vt_analysis_obj.status}).")
                                vt_message = f"Analiz devam ediyor (ID: {analysis_id})."
                        elif vt_analysis_obj == "QuotaExceeded":
                            print("UYARI: VirusTotal API kotası aşıldı (analiz raporu).")
                            vt_decision = "error"
                            vt_message = "Kota aşıldı (analiz raporu)."
                        elif vt_analysis_obj == "AuthError":
                            print("HATA: VirusTotal API anahtarı geçersiz (analiz raporu).")
                            vt_decision = "error"
                            vt_message = "API Anahtarı Hatası (analiz raporu)."
                    except Exception as e:
                        print(f"VirusTotal analiz raporu alınırken hata oluştu: {str(e)}")
                        vt_decision = "error"
                        vt_message = f"Analiz raporu hatası: {str(e)}"
                        
                elif analysis_id == "QuotaExceeded":
                    print("UYARI: VirusTotal API kotası aşıldı (dosya yükleme).")
                    vt_decision = "error"
                    vt_message = "Kota aşıldı (dosya yükleme)."
                elif analysis_id == "AuthError":
                    print("HATA: VirusTotal API anahtarı geçersiz (dosya yükleme).")
                    vt_decision = "error"
                    vt_message = "API Anahtarı Hatası (dosya yükleme)."
            except Exception as e:
                print(f"VirusTotal'a dosya yüklenirken hata oluştu: {str(e)}")
                vt_decision = "error"
                vt_message = f"Dosya yükleme hatası: {str(e)}"

        if vt_report_data:
            vt_decision, vt_message = analyze_vt_scan_results(vt_report_data)
            print(f"VirusTotal Kararı: {vt_decision.upper()} - {vt_message}")
        elif not analysis_pending and vt_decision == "unknown": 
             print(f"VirusTotal Kararı: {vt_decision.upper()} - {vt_message}")

    # Nihai Karar ve Aksiyon
    print("\n--- TARAMA SONUCU ---")
    if is_suspicious_locally and "ZARARLI" in local_scan_reason.upper():
        print(f"NİHAİ KARAR: ZARARLI (Yerel Tespit: {local_scan_reason})")
        if quarantine_file(file_path):
            print(f"'{os.path.basename(file_path)}' karantinaya alındı.")
    elif enable_vt_scan and vt_decision == "malicious":
        print(f"NİHAİ KARAR: ZARARLI (VirusTotal Tespit: {vt_message})")
        if quarantine_file(file_path):
            print(f"'{os.path.basename(file_path)}' karantinaya alındı.")
    elif enable_vt_scan and vt_decision == "suspicious":
        print(f"NİHAİ KARAR: ŞÜPHELİ (VirusTotal Tespit: {vt_message}) - Manuel inceleme önerilir.")
    elif is_suspicious_locally and "ŞÜPHELİ" in local_scan_reason.upper():
        print(f"NİHAİ KARAR: ŞÜPHELİ (Yerel Tespit: {local_scan_reason}) - Manuel inceleme önerilir.")
    elif enable_vt_scan and vt_decision == "clean":
         print(f"NİHAİ KARAR: TEMİZ (VirusTotal: {vt_message})")
    elif not enable_vt_scan and not is_suspicious_locally:
        print("NİHAİ KARAR: TEMİZ (Sadece yerel temel kontroller yapıldı, VT devre dışı.)")
    elif vt_decision == "error":
        print(f"NİHAİ KARAR: HATA (VirusTotal ile iletişimde sorun: {vt_message})")
    else:
        print("NİHAİ KARAR: BİLİNMİYOR / TEMİZ GÖRÜNÜYOR (Mevcut kurallara göre zararlı/şüpheli bulunamadı).")

    print("-----------------------\n") 