import argparse
# Artik os, time ve diger scanner/utils importlarina burada ihtiyac yok,
# scanner_engine.py bunlari hallediyor.
from scanner_engine import scan_single_file

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
