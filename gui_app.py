import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
from ttkthemes import ThemedTk
from PIL import Image, ImageTk
import threading
import os
import asyncio
import sys

# app_logic.py dosyanızın projenizle aynı dizinde olduğunu varsayıyoruz.
from app_logic import AppLogic

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

class AntivirusApp:
    def __init__(self, root):
        self.root = root
        self.current_theme = "arc"  # Varsayılan tema
        self.dark_mode = False  # Varsayılan olarak light mode
        self.root.set_theme(self.current_theme)
        self.root.title("Modern Antivirüs")
        self.root.geometry("850x650") # Pencere boyutunu biraz büyüttük

        # Temel font ayarı
        self.default_font = ("Segoe UI", 10)
        self.header_font = ("Segoe UI", 12, "bold")
        self.button_font = ("Segoe UI", 10, "bold")

        self.style = ttk.Style()
        self.style.configure('.', font=self.default_font)
        self.style.configure('TButton', font=self.button_font, padding=5)
        self.style.configure('Header.TLabel', font=self.header_font)
        self.style.configure('Accent.TButton', font=self.button_font, padding=5) # Özel buton stili
        # Treeview için renk etiketleri
        self.style.configure("Treeview.Heading", font=self.button_font) # Başlık fontu
        self.style.map("TButton",
                       foreground=[('disabled', 'gray')],
                       background=[('disabled', self.style.lookup('TButton', 'background'))])


        self.logic = AppLogic(
            status_callback=self.update_status,
            progress_callback=self.update_progressbar,
            results_callback=self.display_results,
            vt_api_key_missing_callback=self.prompt_for_vt_api_key
            # scan_complete_callback eklenmediği için buton durumları update_status'ta yönetilecek
        )
        self.selected_path = tk.StringVar()
        self.scan_type = tk.StringVar(value="local")

        self.icons = {}
        self.load_icons()

        self.setup_ui()
        self.update_vt_api_key_status()
        self.root.protocol("WM_DELETE_WINDOW", self.on_quit)

    # Tema değiştirme fonksiyonu
    def toggle_theme(self):
        if self.dark_mode:
            # Light mode'a geç
            self.current_theme = "arc"
            self.dark_mode = False
            self.theme_button.config(text="Karanlık Mod")
        else:
            # Dark mode'a geç
            self.current_theme = "equilux"  # veya "black" gibi koyu bir tema
            self.dark_mode = True
            self.theme_button.config(text="Aydınlık Mod")
        
        self.root.set_theme(self.current_theme)
        self.update_theme_colors()

    def update_theme_colors(self):
        # Tema değiştiğinde renk ayarlarını güncelle
        if self.dark_mode:
            # Dark mode renkleri
            bg_color = "#2d2d2d"
            fg_color = "white"
            selected_bg = "#4a6984"
            
            # Treeview renkleri
            self.style.configure("Treeview", background=bg_color, foreground=fg_color, fieldbackground=bg_color)
            self.style.configure("Treeview.Heading", background="#3c3c3c", foreground=fg_color)
            self.style.map('Treeview', background=[('selected', selected_bg)])
            
            # Diğer widget'lar için renkler
            self.style.configure("TFrame", background=bg_color)
            self.style.configure("TLabel", background=bg_color, foreground=fg_color)
            self.style.configure("TLabelframe", background=bg_color, foreground=fg_color)
            self.style.configure("TLabelframe.Label", background=bg_color, foreground=fg_color)
            self.style.configure("TButton", background="#3c3c3c", foreground=fg_color)
            self.style.configure("Accent.TButton", background="#0078D7", foreground=fg_color)
            
            # Sonuç etiketleri
            self.results_tree.tag_configure('infected', background='#8B0000', foreground='white')  # Koyu kırmızı
            self.results_tree.tag_configure('clean', background='#006400', foreground='white')  # Koyu yeşil
            self.results_tree.tag_configure('info', background='#8B8000', foreground='white')  # Koyu sarı
            self.results_tree.tag_configure('error', background='#FF4500', foreground='white')  # Turuncu-kırmızı
        else:
            # Light mode renkleri
            bg_color = "#ffffff"
            fg_color = "black"
            selected_bg = "#4a6984"
            
            # Treeview renkleri
            self.style.configure("Treeview", background=bg_color, foreground=fg_color, fieldbackground=bg_color)
            self.style.configure("Treeview.Heading", background="#f0f0f0", foreground=fg_color)
            self.style.map('Treeview', background=[('selected', selected_bg)])
            
            # Diğer widget'lar için renkler
            self.style.configure("TFrame", background=bg_color)
            self.style.configure("TLabel", background=bg_color, foreground=fg_color)
            self.style.configure("TLabelframe", background=bg_color, foreground=fg_color)
            self.style.configure("TLabelframe.Label", background=bg_color, foreground=fg_color)
            self.style.configure("TButton", background="#f0f0f0", foreground=fg_color)
            self.style.configure("Accent.TButton", background="#0078D7", foreground="white")
            
            # Sonuç etiketleri
            self.results_tree.tag_configure('infected', background='salmon', foreground='black')
            self.results_tree.tag_configure('clean', background='lightgreen', foreground='black')
            self.results_tree.tag_configure('info', background='lightyellow', foreground='black')
            self.results_tree.tag_configure('error', background='orangered', foreground='white')

    def load_icons(self):
        try:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            icon_path_base = os.path.join(base_dir, "icons")
            icon_size = (20, 20) # İkon boyutunu biraz büyüttük

            icon_definitions = {
                "file": "file.png",
                "folder": "folder.png",
                "scan": "scan.png",
                "cancel": "cancel.png",
                "settings": "settings.png",
                "help": "help.png", # Yardım ve Hakkında ikonları için
                "about": "about.png",
                "theme": "theme.png"  # Tema değiştirme ikonu
            }

            for name, filename in icon_definitions.items():
                full_path = os.path.join(icon_path_base, filename)
                if os.path.exists(full_path):
                    img = Image.open(full_path).resize(icon_size, Image.Resampling.LANCZOS)
                    self.icons[name] = ImageTk.PhotoImage(img)
                else:
                    print(f"Uyarı: İkon bulunamadı - {full_path}")
                    self.icons[name] = None # İkon bulunamazsa None ata

        except Exception as e:
            print(f"İkonlar yüklenirken hata oluştu: {e}")
            self.icons = {}

    def setup_ui(self):
        # Ana Çerçeve
        main_frame = ttk.Frame(self.root, padding="15 15 15 15")
        main_frame.pack(expand=True, fill=tk.BOTH)
        main_frame.columnconfigure(0, weight=1)

        # --- Menü Çubuğu ---
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Dosya", menu=file_menu)
        file_menu.add_command(label="Çıkış", command=self.on_quit)

        settings_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Ayarlar", menu=settings_menu)
        settings_menu.add_command(label="VirusTotal API Anahtarı...",
                                  command=self.configure_vt_api_key,
                                  image=self.icons.get("settings"), compound="left")
        settings_menu.add_command(label="Tema Değiştir", 
                                  command=self.toggle_theme,
                                  image=self.icons.get("theme"), compound="left")

        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Yardım", menu=help_menu)
        help_menu.add_command(label="Yardım", command=self.show_help, image=self.icons.get("help"), compound="left")
        help_menu.add_command(label="Hakkında", command=self.show_about, image=self.icons.get("about"), compound="left")


        # --- Tarama Seçenekleri Çerçevesi ---
        scan_options_frame = ttk.LabelFrame(main_frame, text="Tarama Seçenekleri", padding="10 10 10 10")
        scan_options_frame.grid(row=0, column=0, padx=5, pady=(0,10), sticky="ew")
        scan_options_frame.columnconfigure(1, weight=1)

        ttk.Radiobutton(scan_options_frame, text="Yerel Tarama", variable=self.scan_type, value="local").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        ttk.Radiobutton(scan_options_frame, text="VirusTotal Dosya Taraması", variable=self.scan_type, value="virustotal").grid(row=0, column=1, columnspan=2, padx=5, pady=5, sticky="w")

        path_label = ttk.Label(scan_options_frame, text="Dosya/Dizin Yolu:")
        path_label.grid(row=1, column=0, padx=5, pady=(10,5), sticky="w")
        
        path_entry_frame = ttk.Frame(scan_options_frame)
        path_entry_frame.grid(row=1, column=1, columnspan=2, padx=5, pady=(10,5), sticky="ew")
        path_entry_frame.columnconfigure(0, weight=1)

        path_entry = ttk.Entry(path_entry_frame, textvariable=self.selected_path, width=60) # Genişliği artırdık
        path_entry.grid(row=0, column=0, padx=(0,5), sticky="ew")

        button_frame_select = ttk.Frame(path_entry_frame)
        button_frame_select.grid(row=0, column=1, sticky="e")

        self.select_file_button = ttk.Button(button_frame_select, text="Dosya Seç", command=self.select_file, 
                                             image=self.icons.get("file"), compound="left")
        self.select_file_button.pack(side=tk.LEFT, padx=(0,5))
        
        self.select_dir_button = ttk.Button(button_frame_select, text="Dizin Seç", command=self.select_directory,
                                            image=self.icons.get("folder"), compound="left")
        self.select_dir_button.pack(side=tk.LEFT)

        action_buttons_frame = ttk.Frame(scan_options_frame)
        action_buttons_frame.grid(row=2, column=0, columnspan=3, pady=(15,5), sticky="ew") # Butonlar arasına boşluk
        action_buttons_frame.columnconfigure(0, weight=1) # Başlat butonu sola, iptal sağa

        self.start_scan_button = ttk.Button(action_buttons_frame, text="Taramayı Başlat", command=self.start_scan_thread,
                                            style="Accent.TButton", image=self.icons.get("scan"), compound="left")
        if self.icons.get("scan"): # Eğer ikon varsa Accent stili için ek ayar
            self.style.configure("Accent.TButton", foreground="white", background="#0078D7") # Tema rengine göre ayarlanabilir
        self.start_scan_button.grid(row=0, column=0, padx=5, sticky="w")
        
        self.cancel_scan_button = ttk.Button(action_buttons_frame, text="Taramayı İptal Et", command=self.cancel_current_scan,
                                             state="disabled", image=self.icons.get("cancel"), compound="left")
        self.cancel_scan_button.grid(row=0, column=1, padx=5, sticky="e")

        # --- Durum Çerçevesi ---
        status_frame = ttk.LabelFrame(main_frame, text="Durum", padding="10 10 10 10")
        status_frame.grid(row=1, column=0, padx=5, pady=5, sticky="ew")
        status_frame.columnconfigure(0, weight=1)

        self.status_label = ttk.Label(status_frame, text="Başlamak için bir dosya veya dizin seçin ve tarama türünü belirtin.", wraplength=750)
        self.status_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")

        self.progress_bar = ttk.Progressbar(status_frame, orient="horizontal", length=300, mode="determinate")
        self.progress_bar.grid(row=1, column=0, padx=5, pady=(5,2), sticky="ew")
        
        status_bottom_frame = ttk.Frame(status_frame)
        status_bottom_frame.grid(row=2, column=0, padx=5, pady=(2,5), sticky="ew")
        status_bottom_frame.columnconfigure(0, weight=1)
        
        self.vt_api_key_status_label = ttk.Label(status_bottom_frame, text="")
        self.vt_api_key_status_label.grid(row=0, column=0, sticky="w")
        
        # Tema değiştirme butonu
        self.theme_button = ttk.Button(status_bottom_frame, text="Karanlık Mod", command=self.toggle_theme,
                                     image=self.icons.get("theme"), compound="left")
        self.theme_button.grid(row=0, column=1, sticky="e")

        # --- Sonuçlar Çerçevesi ---
        results_frame = ttk.LabelFrame(main_frame, text="Tarama Sonuçları", padding="10 10 10 10")
        results_frame.grid(row=2, column=0, padx=5, pady=5, sticky="nsew")
        main_frame.rowconfigure(2, weight=1)

        columns = ("file", "status", "details")
        self.results_tree = ttk.Treeview(results_frame, columns=columns, show="headings", height=15)
        
        self.results_tree.heading("file", text="Dosya/Dizin Yolu")
        self.results_tree.heading("status", text="Durum")
        self.results_tree.heading("details", text="Ayrıntılar")

        self.results_tree.column("file", width=350, minwidth=200, stretch=tk.YES)
        self.results_tree.column("status", width=120, minwidth=80, stretch=tk.NO, anchor="center")
        self.results_tree.column("details", width=300, minwidth=150, stretch=tk.YES)

        tree_scrollbar_y = ttk.Scrollbar(results_frame, orient="vertical", command=self.results_tree.yview)
        tree_scrollbar_x = ttk.Scrollbar(results_frame, orient="horizontal", command=self.results_tree.xview)
        self.results_tree.configure(yscrollcommand=tree_scrollbar_y.set, xscrollcommand=tree_scrollbar_x.set)

        self.results_tree.grid(row=0, column=0, sticky="nsew")
        tree_scrollbar_y.grid(row=0, column=1, sticky="ns")
        tree_scrollbar_x.grid(row=1, column=0, sticky="ew")

        results_frame.rowconfigure(0, weight=1)
        results_frame.columnconfigure(0, weight=1)
        
        # Renk etiketleri
        self.results_tree.tag_configure('infected', background='salmon', foreground='black')
        self.results_tree.tag_configure('clean', background='lightgreen', foreground='black')
        self.results_tree.tag_configure('info', background='lightyellow', foreground='black')
        self.results_tree.tag_configure('error', background='orangered', foreground='white')
        
        # Tema renklerini ayarla
        if self.dark_mode:
            self.update_theme_colors()

    def select_file(self):
        filepath = filedialog.askopenfilename()
        if filepath:
            self.selected_path.set(filepath)

    def select_directory(self):
        dirpath = filedialog.askdirectory()
        if dirpath:
            self.selected_path.set(dirpath)

    def start_scan_thread(self):
        path = self.selected_path.get()
        scan_type_val = self.scan_type.get()

        if not path:
            messagebox.showerror("Hata", "Lütfen taranacak bir dosya veya dizin seçin.")
            return

        if scan_type_val == "virustotal" and not self.logic.get_vt_api_key():
            self.prompt_for_vt_api_key(missing_on_start=True)
            if not self.logic.get_vt_api_key():
                 messagebox.showerror("Hata", "VirusTotal taraması için API anahtarı gereklidir.")
                 return
        
        for item in self.results_tree.get_children(): # Eski sonuçları temizle
            self.results_tree.delete(item)

        self.update_status(f"{scan_type_val.capitalize()} taraması başlatılıyor: {os.path.basename(path)}")
        self.progress_bar["value"] = 0
        
        self.start_scan_button.config(state="disabled")
        self.select_file_button.config(state="disabled")
        self.select_dir_button.config(state="disabled")
        self.cancel_scan_button.config(state="normal")

        self.logic.reset_cancel_scan_flag()

        thread = threading.Thread(target=self.logic.start_scan, args=(path, scan_type_val))
        thread.daemon = True
        thread.start()

    def cancel_current_scan(self):
        self.logic.cancel_scan()
        self.update_status("Tarama iptal ediliyor...")
        self.cancel_scan_button.config(state="disabled")
        # Diğer butonlar update_status içinde "iptal edildi" mesajıyla aktifleşecek

    def update_status(self, message):
        if self.root is None or not tk.Toplevel.winfo_exists(self.root):
            return
        self.status_label.config(text=message)

        # Tarama bittiğinde veya hata/iptal durumunda butonları aktif et (app_logic.py'de callback olmadığı için)
        msg_lower = message.lower()
        if "tamamlandı" in msg_lower or "hata oluştu" in msg_lower or "iptal edildi" in msg_lower or "bulunamadı" in msg_lower:
            self.start_scan_button.config(state="normal")
            self.select_file_button.config(state="normal")
            self.select_dir_button.config(state="normal")
            self.cancel_scan_button.config(state="disabled")
            if "tamamlandı" in msg_lower and self.progress_bar["value"] < 100 and self.progress_bar["value"] > 0 : #Eğer yarıda bittiyse
                 self.progress_bar["value"] = 100 # Tamamla


    def update_progressbar(self, value):
        if self.root is None or not tk.Toplevel.winfo_exists(self.root):
            return
        self.progress_bar["value"] = value

    def display_results(self, message):
        if self.root is None or not tk.Toplevel.winfo_exists(self.root):
            return
        
        try:
            file_part = ""
            status_part = "Bilinmiyor"
            details_part = message # Varsayılan olarak tüm mesaj ayrıntı
            tag_to_use = 'info'

            if " - Status: " in message:
                parts = message.split(" - Status: ", 1)
                if parts[0].startswith("File: "):
                    file_part = parts[0][len("File: "):].strip()
                else:
                    file_part = parts[0].strip()
                
                status_and_details = parts[1]
                if " - Details: " in status_and_details:
                    status_details_parts = status_and_details.split(" - Details: ", 1)
                    status_part = status_details_parts[0].strip()
                    details_part = status_details_parts[1].strip()
                else:
                    status_part = status_and_details.strip()
            elif message.startswith("Taranan dosya:"): # app_logic'in VT için verdiği format
                 parts = message.split(" - Sonuç: ")
                 file_part = parts[0][len("Taranan dosya:"):].strip()
                 if len(parts) > 1:
                     status_part = parts[1].strip()
                     details_part = status_part # VT için detay ve durum genelde aynı
                 else:
                     status_part = "Bekleniyor..." # Henüz sonuç gelmemiş olabilir
            elif "API anahtarı" in message.lower(): # API anahtarı mesajları
                file_part = "Sistem Bilgisi"
                status_part = "API Anahtarı"
                # details_part zaten message
            else: # Genel mesajlar
                file_part = "Bilgi"
                status_part = "Sistem"
                # details_part zaten message

            status_lower = status_part.lower()
            if "infected" in status_lower or "tehdit" in status_lower or "malicious" in status_lower or "suspicious" in status_lower:
                tag_to_use = 'infected'
            elif "clean" in status_lower or "temiz" in status_lower or "harmless" in status_lower or "unrated" in status_lower:
                tag_to_use = 'clean'
            elif "hata" in status_lower or "error" in status_lower:
                tag_to_use = 'error'

            self.results_tree.insert("", "end", values=(file_part, status_part, details_part), tags=(tag_to_use,))
            self.results_tree.yview_moveto(1) # Son eklenen kaydı görünür yap

        except Exception as e:
            self.results_tree.insert("", "end", values=("Hata", "Mesaj Ayrıştırma", str(e)), tags=('error',))
            print(f"Sonuç ('{message}') ayrıştırma hatası: {e}")


    def configure_vt_api_key(self):
        current_key = self.logic.get_vt_api_key() or ""
        api_key = simpledialog.askstring("VirusTotal API Anahtarı", 
                                         "Lütfen VirusTotal API anahtarınızı girin:",
                                         initialvalue=current_key,
                                         parent=self.root)
        if api_key is not None: # Kullanıcı iptal etmediyse (boş string girebilir)
            self.logic.set_vt_api_key(api_key)
            if api_key:
                 messagebox.showinfo("Bilgi", "VirusTotal API anahtarı kaydedildi.", parent=self.root)
            else:
                 messagebox.showwarning("Bilgi", "VirusTotal API anahtarı silindi.", parent=self.root)

        self.update_vt_api_key_status()

    def update_vt_api_key_status(self):
        if self.logic.get_vt_api_key():
            self.vt_api_key_status_label.config(text="VirusTotal API Anahtarı: Ayarlandı", foreground="green")
        else:
            self.vt_api_key_status_label.config(text="VirusTotal API Anahtarı: Ayarlanmadı (Ayarlar menüsünden girin)", foreground="red")

    def prompt_for_vt_api_key(self, missing_on_start=False):
        if missing_on_start:
            msg = "VirusTotal taraması için API anahtarı gerekli. Şimdi girmek ister misiniz?"
        else:
            msg = "VirusTotal API anahtarı bulunamadı veya geçersiz. Ayarlamak ister misiniz?"
        
        if messagebox.askyesno("API Anahtarı Eksik", msg, parent=self.root):
            self.configure_vt_api_key()


    def show_help(self):
        help_text = """
Antivirüs Uygulaması Kullanım Kılavuzu:

1. Tarama Türünü Seçin:
   - Yerel Tarama: Bilgisayarınızdaki dosyaları yerel imza veritabanı ile tarar.
   - VirusTotal Dosya Taraması: Seçilen dosyayı VirusTotal servisine göndererek tarar (İnternet bağlantısı ve API anahtarı gerektirir).

2. Dosya veya Dizin Seçin:
   - "Dosya Seç" butonu ile tek bir dosya seçin.
   - "Dizin Seç" butonu ile bir klasördeki tüm dosyaları taramak için klasör seçin.

3. Taramayı Başlatın:
   - "Taramayı Başlat" butonuna tıklayın.

4. Sonuçları İnceleyin:
   - Tarama durumu ve ilerlemesi "Durum" bölümünde gösterilir.
   - Detaylı sonuçlar "Tarama Sonuçları" listesinde görüntülenir.

VirusTotal API Anahtarı:
   - Ayarlar menüsünden VirusTotal API anahtarınızı girebilir veya güncelleyebilirsiniz. Bu anahtar, VirusTotal taramaları için gereklidir.
"""
        messagebox.showinfo("Yardım", help_text, parent=self.root)

    def show_about(self):
        about_text = """
Modern Antivirüs Uygulaması
Sürüm: 1.0 (GUI Geliştirilmiş)
Geliştirici: [Sinan Soytürk]

Bu uygulama, yerel ve VirusTotal tabanlı tarama yetenekleri sunar.
"""
        messagebox.showinfo("Hakkında", about_text, parent=self.root)

    def on_quit(self):
        if self.logic.is_scan_running(): # app_logic.py'ye is_scan_running() eklenmeli
            if messagebox.askyesno("Çıkış Onayı", "Devam eden bir tarama var. Çıkmak istediğinize emin misiniz?", parent=self.root):
                self.logic.cancel_scan() # İptal etmeyi dene
                self.root.destroy()
            else:
                return # Çıkışı iptal et
        self.root.destroy()


if __name__ == "__main__":
    themed_root = ThemedTk()
    app = AntivirusApp(themed_root)
    themed_root.mainloop()