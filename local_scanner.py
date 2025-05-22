# antivirus_projesi/local_scanner.py

import hashlib
import math
import os

MALWARE_HASHES_FILE = "malware_hashes.txt" # Yerel hash veritabanı dosyası
LOCAL_MALWARE_HASHES = set()

def load_local_malware_hashes():
    """Yerel zararlı hash veritabanını dosyadan yükler."""
    global LOCAL_MALWARE_HASHES
    LOCAL_MALWARE_HASHES = set() # Her yüklemede sıfırla
    if os.path.exists(MALWARE_HASHES_FILE):
        try:
            with open(MALWARE_HASHES_FILE, "r") as f:
                for line in f:
                    hash_val = line.strip()
                    if hash_val and not hash_val.startswith("#"): # Yorum satırlarını ve boşlukları atla
                        LOCAL_MALWARE_HASHES.add(hash_val)
            print(f"{len(LOCAL_MALWARE_HASHES)} adet yerel zararlı hash yüklendi.")
        except Exception as e:
            print(f"Yerel zararlı hash veritabanı ({MALWARE_HASHES_FILE}) yüklenirken hata: {e}")
    else:
        print(f"Yerel zararlı hash veritabanı ({MALWARE_HASHES_FILE}) bulunamadı. Boş set ile devam ediliyor.")

def get_file_hash(filepath, algorithm="sha256", block_size=65536):
    """Belirtilen algoritmayı kullanarak bir dosyanın hash'ini hesaplar."""
    hasher = hashlib.new(algorithm)
    try:
        with open(filepath, 'rb') as f:
            for block in iter(lambda: f.read(block_size), b''):
                hasher.update(block)
        return hasher.hexdigest()
    except IOError:
        # print(f"Hata: {filepath} dosyası okunamadı (get_file_hash)")
        return None
    except Exception as e:
        # print(f"{filepath} hashlenirken beklenmedik bir hata oluştu: {e}")
        return None

def check_against_local_db(file_hash):
    """Verilen hash'i yerel veritabanıyla karşılaştırır."""
    if not LOCAL_MALWARE_HASHES: # Eğer yüklenmemişse veya boşsa yükle
        load_local_malware_hashes()
    return file_hash in LOCAL_MALWARE_HASHES

def calculate_entropy(data_bytes):
    """Bir byte dizisinin Shannon entropisini hesaplar."""
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
    """Dosyanın entropisini hesaplar ve eşik değerine göre şüpheli olup olmadığını belirler."""
    try:
        with open(filepath, 'rb') as f:
            file_data = f.read()
        if not file_data:
            return False, 0.0 # Boş dosya şüpheli değil, entropi 0
        
        entropy_value = calculate_entropy(file_data)
        is_suspicious = entropy_value > threshold
        return is_suspicious, entropy_value
    except IOError:
        # print(f"Entropi hesaplanırken {filepath} okunamadı.")
        return False, -1.0 # Okuma hatası
    except Exception as e:
        # print(f"Entropi hesaplanırken hata ({filepath}): {e}")
        return False, -1.0 # Başka bir hata

# Başlangıçta yerel hash'leri yükle
load_local_malware_hashes()

if __name__ == "__main__":
    print("Yerel Tarayıcı Modülü Testi")
    # Örnek bir malware_hashes.txt dosyası oluşturun:
    # # Bu bir yorumdur
    # eicar_sha256_hash_buraya
    # baska_bir_zararli_hash
    with open(MALWARE_HASHES_FILE, "w") as f:
        f.write("# EICAR Test Dosyası SHA256\n")
        f.write("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f\n")
    
    load_local_malware_hashes() # Tekrar yükle
    print("Yüklü Yerel Hashler:", LOCAL_MALWARE_HASHES)

    eicar_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    print(f"EICAR hash ({eicar_hash}) yerel DB'de var mı? {check_against_local_db(eicar_hash)}")
    print(f"Sahte hash ('abc') yerel DB'de var mı? {check_against_local_db('abc')}")

    # Entropi testi için bir dosya oluşturun
    test_file_entropy = "entropy_test.txt"
    with open(test_file_entropy, "wb") as f:
        f.write(os.urandom(1024)) # Rastgele baytlar yüksek entropi verir
    
    is_susp, ent_val = check_entropy_heuristic(test_file_entropy, threshold=7.0)
    print(f"'{test_file_entropy}' entropi: {ent_val:.2f}, Şüpheli (eşik > 7.0): {is_susp}")
    
    if os.path.exists(test_file_entropy):
        os.remove(test_file_entropy)
    if os.path.exists(MALWARE_HASHES_FILE): # Test sonrası temizle
        os.remove(MALWARE_HASHES_FILE)