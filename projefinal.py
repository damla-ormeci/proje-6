import customtkinter as ctk
from tkinter import messagebox, filedialog
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import os

# --- KRİPTOGRAFİ MANTIĞI ---

def anahtar_uret(parola):
    return hashlib.sha256(parola.encode()).digest()

def aes_sifrele(veri, anahtar):
    cipher = AES.new(anahtar, AES.MODE_CBC)
    return cipher.iv + cipher.encrypt(pad(veri, AES.block_size))

def aes_coz(toplam_veri, anahtar):
    iv = toplam_veri[:16]
    sifreli_kisim = toplam_veri[16:]
    cipher = AES.new(anahtar, AES.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(sifreli_kisim), AES.block_size)

# --- ARAYÜZ ---

class TozPembeAES(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Renk Paleti
        self.toz_pembe = "#FFB6C1"
        self.arka_plan = "#FFF5F7"
        self.vurgu_pembe = "#DB7093"
        self.buton_pembe = "#FF69B4"

        self.title("Soft Pink File Crypt Pro")
        self.geometry("550x850")
        self.configure(fg_color=self.arka_plan)
        ctk.set_appearance_mode("light")
        
        # Başlık
        ctk.CTkLabel(self, text="🌸 Soft File Crypt 🌸", font=("Segoe UI", 28, "bold"), text_color=self.vurgu_pembe).pack(pady=20)

        # --- MEDYA VE DOSYA BÖLÜMÜ (Görsel/Video) ---
        self.media_frame = ctk.CTkFrame(self, fg_color="white", border_color=self.toz_pembe, border_width=2)
        self.media_frame.pack(pady=10, padx=20, fill="x")
        
        ctk.CTkLabel(self.media_frame, text="Görsel & Video Şifreleme (.pink)", font=("Segoe UI", 14, "bold"), text_color=self.vurgu_pembe).pack(pady=5)
        
        self.media_btn_frame = ctk.CTkFrame(self.media_frame, fg_color="transparent")
        self.media_btn_frame.pack(pady=10)

        ctk.CTkButton(self.media_btn_frame, text="📁 Medya Şifrele", command=lambda: self.medya_islem("sifrele"), 
                      fg_color=self.buton_pembe, hover_color=self.vurgu_pembe).grid(row=0, column=0, padx=5)
        
        ctk.CTkButton(self.media_btn_frame, text="🔓 Medya Çöz", command=lambda: self.medya_islem("coz"), 
                      fg_color=self.toz_pembe, hover_color=self.vurgu_pembe).grid(row=0, column=1, padx=5)

        # --- METİN BÖLÜMÜ ---
        ctk.CTkLabel(self, text="Hızlı Metin İşlemleri", font=("Segoe UI", 13, "bold"), text_color=self.vurgu_pembe).pack(pady=(15,0))
        
        self.input_text = ctk.CTkTextbox(self, width=450, height=120, border_color=self.toz_pembe, border_width=2, fg_color="white")
        self.input_text.pack(pady=10)

        # .txt'den Metin Çekme Butonu
        ctk.CTkButton(self, text="📄 .txt Dosyasından Metin Çek (Kutuya Aktar)", command=self.dosyadan_metin_oku, 
                      fg_color=self.vurgu_pembe, hover_color=self.buton_pembe, width=450).pack(pady=5)

        self.pass_entry = ctk.CTkEntry(self, placeholder_text="Ortak Şifre / Key", show="*", width=450, border_color=self.toz_pembe, fg_color="white")
        self.pass_entry.pack(pady=15)

        self.output_text = ctk.CTkTextbox(self, width=450, height=120, border_color=self.toz_pembe, border_width=2, fg_color="white")
        self.output_text.pack(pady=10)

        # Metin Butonları
        self.btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.btn_frame.pack(pady=15)

        ctk.CTkButton(self.btn_frame, text="Metni Şifrele ✨", command=self.sifrele_islem, fg_color=self.buton_pembe).grid(row=0, column=0, padx=10)
        ctk.CTkButton(self.btn_frame, text="Metni Çöz 🔓", command=self.coz_islem, fg_color=self.toz_pembe).grid(row=0, column=1, padx=10)

    # --- FONKSİYONLAR ---

    def dosyadan_metin_oku(self):
        """Sadece .txt içeriğini okur ve kutuya yapıştırır."""
        yol = filedialog.askopenfilename(filetypes=[("Metin Dosyaları", "*.txt")])
        if yol:
            try:
                with open(yol, "r", encoding="utf-8") as f:
                    self.input_text.delete("0.0", "end")
                    self.input_text.insert("0.0", f.read())
                messagebox.showinfo("Bilgi", "Metin başarıyla kutuya aktarıldı. 🎀")
            except Exception as e:
                messagebox.showerror("Hata", "Dosya okunamadı.")

    def medya_islem(self, mod):
        """Görsel ve videoları .pink uzantısı ile şifreler/çözer."""
        parola = self.pass_entry.get()
        if not parola:
            messagebox.showwarning("Uyarı", "Lütfen önce bir şifre girin! 🌸")
            return

        yol = filedialog.askopenfilename(title="Dosya Seç")
        if not yol: return

        try:
            anahtar = anahtar_uret(parola)
            with open(yol, "rb") as f:
                veri = f.read()

            if mod == "sifrele":
                sonuc = aes_sifrele(veri, anahtar)
                yeni_yol = yol + ".pink"
            else:
                sonuc = aes_coz(veri, anahtar)
                yeni_yol = yol.replace(".pink", "")
                if yeni_yol == yol:
                    yeni_yol = filedialog.asksaveasfilename(title="Farklı Kaydet")

            if yeni_yol:
                with open(yeni_yol, "wb") as f:
                    f.write(sonuc)
                messagebox.showinfo("Başarılı", f"İşlem tamamlandı!\nYeni dosya: {yeni_yol} 🎀")
        except:
            messagebox.showerror("Hata", "Şifre yanlış veya dosya bozuk.")

    def sifrele_islem(self):
        try:
            p = self.pass_entry.get()
            if not p: return
            res = aes_sifrele(self.input_text.get("0.0", "end-1c").encode(), anahtar_uret(p))
            self.output_text.delete("0.0", "end")
            self.output_text.insert("0.0", res.hex())
        except: messagebox.showerror("Hata", "Başarısız.")

    def coz_islem(self):
        try:
            p = self.pass_entry.get()
            hex_v = self.output_text.get("0.0", "end-1c")
            res = aes_coz(bytes.fromhex(hex_v), anahtar_uret(p))
            self.input_text.delete("0.0", "end")
            self.input_text.insert("0.0", res.decode())
        except: messagebox.showerror("Hata", "Şifre Yanlış! 🎀")

if __name__ == "__main__":
    app = TozPembeAES()
    app.mainloop()
