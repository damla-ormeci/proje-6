import customtkinter as ctk
from tkinter import messagebox
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib

# --- KRİPTOGRAFİ MANTIĞI (SADE AES-256) ---

def anahtar_uret(parola):
    # Parolayı 32 byte'lık sabit bir AES anahtarına dönüştürür
    return hashlib.sha256(parola.encode()).digest()

def aes_sifrele(veri, anahtar):
    cipher = AES.new(anahtar, AES.MODE_CBC)
    # IV (16 byte) + Şifreli Veri birleştirilerek döndürülür
    return cipher.iv + cipher.encrypt(pad(veri, AES.block_size))

def aes_coz(toplam_veri, anahtar):
    iv = toplam_veri[:16]           # İlk 16 byte IV'dir
    sifreli_kisim = toplam_veri[16:] # Geri kalanı şifreli metin
    cipher = AES.new(anahtar, AES.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(sifreli_kisim), AES.block_size)

# --- TOZ PEMBE ARAYÜZ ---

class TozPembeAES(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Renk Paleti (Toz Pembe Teması)
        self.toz_pembe = "#FFB6C1"    # Light Pink / Toz Pembe
        self.arka_plan = "#FFF5F7"    # Çok açık toz pembe (Blush)
        self.vurgu_pembe = "#DB7093"  # Pale Violet Red (Yazılar için)
        self.buton_pembe = "#FF69B4"  # Hot Pink

        self.title("Soft Pink AES")
        self.geometry("500x550")
        
        # Ana pencere rengini toz pembe yap
        self.configure(fg_color=self.arka_plan)
        ctk.set_appearance_mode("light")
        
        # Başlık
        self.label = ctk.CTkLabel(self, text="🌸 Soft Crypt 🌸", 
                                  font=("Segoe UI", 30, "bold"), 
                                  text_color=self.vurgu_pembe)
        self.label.pack(pady=(30, 20))

        # Giriş Metni Alanı
        ctk.CTkLabel(self, text="Mesajınız:", text_color="#888", font=("Arial", 12, "bold")).pack()
        self.input_text = ctk.CTkTextbox(self, width=400, height=100, 
                                         border_color=self.toz_pembe, border_width=2,
                                         fg_color="white")
        self.input_text.pack(pady=10)

        # Şifre Girişi
        self.pass_entry = ctk.CTkEntry(self, placeholder_text="Anahtar Şifre", 
                                       show="*", width=400, 
                                       border_color=self.toz_pembe,
                                       fg_color="white")
        self.pass_entry.pack(pady=10)

        # Butonlar
        self.btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.btn_frame.pack(pady=20)

        self.sifrele_btn = ctk.CTkButton(self.btn_frame, text="Şifrele ✨", 
                                         command=self.sifrele_islem, 
                                         fg_color=self.buton_pembe, 
                                         hover_color=self.vurgu_pembe)
        self.sifrele_btn.grid(row=0, column=0, padx=10)

        self.coz_btn = ctk.CTkButton(self.btn_frame, text="Çöz 🔓", 
                                     command=self.coz_islem, 
                                     fg_color=self.toz_pembe, 
                                     text_color="white",
                                     hover_color=self.vurgu_pembe)
        self.coz_btn.grid(row=0, column=1, padx=10)

        # Çıkış Metni Alanı (Hex)
        ctk.CTkLabel(self, text="Şifreli Sonuç:", text_color="#888", font=("Arial", 12, "bold")).pack()
        self.output_text = ctk.CTkTextbox(self, width=400, height=100, 
                                          border_color=self.toz_pembe, border_width=2,
                                          fg_color="white")
        self.output_text.pack(pady=10)

    def sifrele_islem(self):
        try:
            parola = self.pass_entry.get()
            if not parola:
                messagebox.showwarning("Uyarı", "Lütfen bir şifre girin! 🌸")
                return
                
            anahtar = anahtar_uret(parola)
            metin = self.input_text.get("0.0", "end-1c").encode('utf-8')
            
            sifreli_toplam = aes_sifrele(metin, anahtar)
            
            self.output_text.delete("0.0", "end")
            self.output_text.insert("0.0", sifreli_toplam.hex())
        except Exception as e:
            messagebox.showerror("Hata", "Şifreleme sırasında bir hata oluştu.")

    def coz_islem(self):
        try:
            parola = self.pass_entry.get()
            hex_veri = self.output_text.get("0.0", "end-1c")
            
            if not hex_veri: return

            anahtar = anahtar_uret(parola)
            cozulmus = aes_coz(bytes.fromhex(hex_veri), anahtar)
            
            self.input_text.delete("0.0", "end")
            self.input_text.insert("0.0", cozulmus.decode('utf-8'))
        except:
            messagebox.showerror("Hata", "Şifre yanlış veya veri bozuk! 🎀")

if __name__ == "__main__":
    app = TozPembeAES()
    app.mainloop()