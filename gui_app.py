import customtkinter
import tkinter
from tkinter import filedialog
import os
import threading
import asyncio
import queue
from scanner_engine import scan_single_file # Arka uç tarama fonksiyonumuzu import ediyoruz
# API anahtarının ve diğer ayarların main.py veya ilgili modüller üzerinden
# zaten yüklendiğini varsayıyoruz.

# CustomTkinter ayarları
customtkinter.set_appearance_mode("Dark") # Temayı koyu yap
customtkinter.set_default_color_theme("green") # Renk temasını yeşil yap

class App(customtkinter.CTk):
    def __init__(self):
        super().__init__()

        self.title("Modern Antivirüs")
        self.geometry("800x600")

        self.selected_file_path = ""
        
        # Çıktı kuyruğu - thread'ler arasında güvenli iletişim için
        self.output_queue = queue.Queue()
        # 100ms'de bir çıktı kuyruğunu kontrol et
        self.after(100, self.check_output_queue)

        # Ana Çerçeve
        self.main_frame = customtkinter.CTkFrame(self)
        self.main_frame.pack(pady=20, padx=20, fill="both", expand=True)

        # Dosya Seçme Alanı
        self.file_selection_frame = customtkinter.CTkFrame(self.main_frame)
        self.file_selection_frame.pack(pady=10, padx=10, fill="x")

        self.select_file_button = customtkinter.CTkButton(
            self.file_selection_frame,
            text="Dosya Seç",
            command=self.select_file
        )
        self.select_file_button.pack(side="left", padx=(0, 10))

        self.selected_file_label = customtkinter.CTkLabel(
            self.file_selection_frame,
            text="Henüz dosya seçilmedi."
        )
        self.selected_file_label.pack(side="left", fill="x", expand=True)

        # Tarama Butonu
        self.scan_button = customtkinter.CTkButton(
            self.main_frame,
            text="Seçili Dosyayı Tara",
            command=self.start_scan_thread,
            state="disabled" # Başlangıçta pasif
        )
        self.scan_button.pack(pady=10)

        # Sonuç Alanı
        self.results_textbox = customtkinter.CTkTextbox(
            self.main_frame,
            wrap="word",
            height=300,
            state="disabled" # Başlangıçta düzenlenemez
        )
        self.results_textbox.pack(pady=10, padx=10, fill="both", expand=True)

        # Durum Çubuğu
        self.status_label = customtkinter.CTkLabel(self.main_frame, text="Hazır.")
        self.status_label.pack(pady=5, side="bottom", fill="x")

    def select_file(self):
        file_path = filedialog.askopenfilename(
            title="Taranacak Dosyayı Seçin",
            filetypes=(("Tüm Dosyalar", "*.*"),
                       ("Executable Dosyalar", "*.exe"),
                       ("PDF Belgeleri", "*.pdf"))
        )
        if file_path:
            self.selected_file_path = file_path
            self.selected_file_label.configure(text=os.path.basename(file_path))
            self.scan_button.configure(state="normal") # Dosya seçilince butonu aktif et
            self.results_textbox.configure(state="normal")
            self.results_textbox.delete("1.0", "end")
            self.results_textbox.insert("1.0", f"Seçilen dosya: {os.path.basename(file_path)}\n")
            self.results_textbox.configure(state="disabled")
            self.status_label.configure(text=f"'{os.path.basename(file_path)}' seçildi. Taramaya hazır.")
        else:
            self.selected_file_path = ""
            self.selected_file_label.configure(text="Dosya seçilmedi.")
            self.scan_button.configure(state="disabled")
            self.status_label.configure(text="Dosya seçimi iptal edildi.")

    def update_results(self, message):
        """Sonuçları thread-safe bir şekilde günceller."""
        self.results_textbox.configure(state="normal")
        self.results_textbox.insert("end", message + "\n")
        self.results_textbox.see("end") # En sona kaydır
        self.results_textbox.configure(state="disabled")

    def set_status(self, message):
        """Durum etiketini thread-safe bir şekilde günceller."""
        self.status_label.configure(text=message)
        
    def check_output_queue(self):
        """Düzenli olarak çıktı kuyruğunu kontrol eder ve GUI'yi günceller."""
        try:
            # Kuyrukta mesaj varsa al
            while not self.output_queue.empty():
                message_type, message = self.output_queue.get_nowait()
                
                if message_type == "results":
                    self.update_results(message)
                elif message_type == "status":
                    self.set_status(message)
                elif message_type == "scan_completed":
                    self.scan_button.configure(state="normal")
                
                self.output_queue.task_done()
        except Exception as e:
            print(f"Çıktı kuyruğu işlenirken hata: {e}")
        finally:
            # Her durumda kendini tekrar zamanla
            self.after(100, self.check_output_queue)

    def scan_file_task(self):
        """Gerçek tarama işlemini yapan ve sonuçları güncelleyen fonksiyon."""
        if not self.selected_file_path:
            self.output_queue.put(("results", "Hata: Taranacak dosya seçilmedi."))
            self.output_queue.put(("status", "Hata: Dosya seçilmedi."))
            self.output_queue.put(("scan_completed", None))
            return

        self.output_queue.put(("status", f"'{os.path.basename(self.selected_file_path)}' taranıyor..."))

        # stdout'u yakalamak için bir yol
        import io
        import sys
        old_stdout = sys.stdout
        sys.stdout = captured_output = io.StringIO()

        try:
            # scan_single_file çağrısı
            scan_single_file(
                self.selected_file_path,
                force_vt_upload=False, # GUI'den ayarlanabilir hale getirilebilir
                enable_vt_scan=True,
                enable_local_scan=True,
                enable_entropy_scan=True
            )
            scan_output = captured_output.getvalue()
            self.output_queue.put(("results", scan_output))
            self.output_queue.put(("status", f"'{os.path.basename(self.selected_file_path)}' taraması tamamlandı."))

        except Exception as e:
            self.output_queue.put(("results", f"Tarama sırasında bir hata oluştu: {str(e)}"))
            self.output_queue.put(("status", "Tarama hatası."))
        finally:
            sys.stdout = old_stdout # stdout'u geri yükle
            self.output_queue.put(("scan_completed", None))

    def start_scan_thread(self):
        """Tarama işlemini ayrı bir thread'de başlatır."""
        if not self.selected_file_path:
            tkinter.messagebox.showerror("Hata", "Lütfen önce bir dosya seçin.")
            return

        # Sonuçları temizle
        self.results_textbox.configure(state="normal")
        self.results_textbox.delete("1.0", "end")
        self.results_textbox.insert("1.0", f"'{os.path.basename(self.selected_file_path)}' için tarama başlatılıyor...\n")
        self.results_textbox.configure(state="disabled")
        
        # Tarama başladığında butonu devre dışı bırak
        self.scan_button.configure(state="disabled")

        # Taramayı yeni bir thread'de çalıştır
        scan_thread = threading.Thread(target=self.scan_file_task, daemon=True)
        scan_thread.start()

if __name__ == "__main__":
    app = App()
    app.mainloop() 