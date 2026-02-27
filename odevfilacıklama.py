import customtkinter as ctk
from tkinter import messagebox, filedialog
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import os

# ==========================================
# --- 1. KRİPTOGRAFİ (ŞİFRELEME) MANTIĞI ---
# ==========================================

def anahtar_uret(parola):
    """
    Kullanıcının girdiği basit şifreyi (ör: '1234'), 
    AES-256 için gerekli olan 32 byte'lık karmaşık bir anahtara dönüştürür.
    """
    return hashlib.sha256(parola.encode()).digest()

def aes_sifrele(veri, anahtar):
    """
    Veriyi AES-CBC modunda şifreler. 
    Güvenlik için rastgele bir IV (Başlangıç Vektörü) üretir ve şifreli verinin başına ekler.
    """
    cipher = AES.new(anahtar, AES.MODE_CBC)
    # IV (16 byte) + Şifrelenmiş Metin (Dolgulanmış)
    return cipher.iv + cipher.encrypt(pad(veri, AES.block_size))

def aes_coz(toplam_veri, anahtar):
    """
    Şifreli paketi alır, ilk 16 byte'lık IV'yi ayırır ve kalan kısmı anahtar yardımıyla çözer.
    """
    iv = toplam_veri[:16]           # Paketin başındaki 16 byte'ı IV olarak al
    sifreli_kisim = toplam_veri[16:] # Kalan kısmı şifreli metin olarak al
    cipher = AES.new(anahtar, AES.MODE_CBC, iv=iv)
    # Çözülen veriden dolgu (padding) kısmını atarak orijinal metne ulaşır
    return unpad(cipher.decrypt(sifreli_kisim), AES.block_size)

# ==========================================
# --- 2. KULLANICI ARAYÜZÜ (UI) TASARIMI ---
# ==========================================

class TozPembeAES(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Toz Pembe Renk Teması Tanımlamaları
        self.toz_pembe = "#FFB6C1"
        self.arka_plan = "#FFF5F7"
        self.vurgu_pembe = "#DB7093"
        self.buton_pembe = "#FF69B4"

        # Pencere Genel Ayarları
        self.title("Soft Pink File Crypt")
        self.geometry("550x700")
        self.configure(fg_color=self.arka_plan) # Arka planı toz pembe yap
        ctk.set_appearance_mode("light")         # Aydınlık (Soft) tema
        
        # Başlık Bölümü
        ctk.CTkLabel(self, text="🌸 Soft File Crypt 🌸", 
                     font=("Segoe UI", 28, "bold"), 
                     text_color=self.vurgu_pembe).pack(pady=20)

        # --- Dosya İşlem Paneli (Gözat ve Kaydet) ---
        self.file_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.file_frame.pack(pady=10)

        self.dosya_oku_btn = ctk.CTkButton(self.file_frame, text="Dosyadan Metin Çek 📄", 
                                           command=self.dosya_oku, 
                                           fg_color="white", text_color=self.vurgu_pembe, 
                                           border_color=self.toz_pembe, border_width=2)
        self.dosya_oku_btn.grid(row=0, column=0, padx=5)

        self.dosya_kaydet_btn = ctk.CTkButton(self.file_frame, text="Sonucu Kaydet 💾", 
                                              command=self.dosya_kaydet, 
                                              fg_color="white", text_color=self.vurgu_pembe, 
                                              border_color=self.toz_pembe, border_width=2)
        self.dosya_kaydet_btn.grid(row=0, column=1, padx=5)

        # Üst Metin Kutusu (Giriş)
        ctk.CTkLabel(self, text="Giriş Metni:", text_color=self.vurgu_pembe).pack()
        self.input_text = ctk.CTkTextbox(self, width=450, height=120, border_color=self.toz_pembe, border_width=2, fg_color="white")
        self.input_text.pack(pady=10)

        # Anahtar Şifre Girişi
        self.pass_entry = ctk.CTkEntry(self, placeholder_text="Gizli Anahtar Şifreniz", 
                                       show="*", width=450, border_color=self.toz_pembe, fg_color="white")
        self.pass_entry.pack(pady=10)

        # Şifrele ve Çöz Butonları
        self.btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.btn_frame.pack(pady=15)

        ctk.CTkButton(self.btn_frame, text="Şifrele ✨", command=self.sifrele_islem, 
                     fg_color=self.buton_pembe, hover_color=self.vurgu_pembe).grid(row=0, column=0, padx=10)
        
        ctk.CTkButton(self.btn_frame, text="Çöz 🔓", command=self.coz_islem, 
                     fg_color=self.toz_pembe, text_color="white", hover_color=self.vurgu_pembe).grid(row=0, column=1, padx=10)

        # Alt Metin Kutusu (Çıkış/Hex)
        ctk.CTkLabel(self, text="Şifrelenmiş Sonuç (Hex):", text_color=self.vurgu_pembe).pack()
        self.output_text = ctk.CTkTextbox(self, width=450, height=120, border_color=self.toz_pembe, border_width=2, fg_color="white")
        self.output_text.pack(pady=10)

    # --- DOSYA SEÇME VE KAYDETME FONKSİYONLARI ---

    def dosya_oku(self):
        """Bilgisayardan .txt dosyası seçer ve içeriğini üst kutuya yazar."""
        dosya_yolu = filedialog.askopenfilename(filetypes=[("Metin Dosyaları", "*.txt")])
        if dosya_yolu:
            try:
                with open(dosya_yolu, "r", encoding="utf-8") as f:
                    self.input_text.delete("0.0", "end")
                    self.input_text.insert("0.0", f.read())
            except Exception as e:
                messagebox.showerror("Hata", f"Dosya açılamadı! 🌸")

    def dosya_kaydet(self):
        """Alt kutudaki şifreli metni bir dosyaya kaydeder."""
        icerik = self.output_text.get("0.0", "end-1c")
        if not icerik:
            messagebox.showwarning("Uyarı", "Kaydedilecek bir veri yok!")
            return
        dosya_yolu = filedialog.asksaveasfilename(defaultextension=".txt")
        if dosya_yolu:
            with open(dosya_yolu, "w", encoding="utf-8") as f:
                f.write(icerik)
            messagebox.showinfo("Başarılı", "Sihirli dosyanız kaydedildi! 💾")

    # --- ŞİFRELEME VE ÇÖZME TETİKLEYİCİLERİ ---

    def sifrele_islem(self):
        """Kullanıcı butona bastığında AES şifreleme sürecini başlatır."""
        try:
            parola = self.pass_entry.get()
            if not parola:
                messagebox.showwarning("Uyarı", "Önce bir şifre girmelisin! 🌸")
                return
            anahtar = anahtar_uret(parola)
            metin = self.input_text.get("0.0", "end-1c").encode('utf-8')
            sifreli = aes_sifrele(metin, anahtar)
            
            # Sonucu kullanıcıya HEX formatında göster (Okunabilir olması için)
            self.output_text.delete("0.0", "end")
            self.output_text.insert("0.0", sifreli.hex())
        except:
            messagebox.showerror("Hata", "Şifreleme yapılamadı.")

    def coz_islem(self):
        """Hex verisini alır ve anahtarla orijinal metne geri döndürür."""
        try:
            parola = self.pass_entry.get()
            hex_veri = self.output_text.get("0.0", "end-1c")
            if not hex_veri: return
            
            anahtar = anahtar_uret(parola)
            # Hex string'i tekrar byte verisine çevir
            cozulmus = aes_coz(bytes.fromhex(hex_veri), anahtar)
            
            # Çözülen metni üst kutuya geri yaz
            self.input_text.delete("0.0", "end")
            self.input_text.insert("0.0", cozulmus.decode('utf-8'))
        except:
            messagebox.showerror("Hata", "Yanlış anahtar veya bozuk veri! 🎀")

if __name__ == "__main__":
    app = TozPembeAES()
    app.mainloop()