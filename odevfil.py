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

        self.title("Soft Pink File Crypt")
        self.geometry("550x700")
        self.configure(fg_color=self.arka_plan)
        ctk.set_appearance_mode("light")
        
        # Başlık
        ctk.CTkLabel(self, text="🌸 Soft File Crypt 🌸", font=("Segoe UI", 28, "bold"), text_color=self.vurgu_pembe).pack(pady=20)

        # --- Dosya Seçme Bölümü ---
        self.file_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.file_frame.pack(pady=10)

        self.dosya_oku_btn = ctk.CTkButton(self.file_frame, text="Dosyadan Metin Çek 📄", command=self.dosya_oku, 
                                           fg_color="white", text_color=self.vurgu_pembe, border_color=self.toz_pembe, border_width=2, hover_color="#fce4ec")
        self.dosya_oku_btn.grid(row=0, column=0, padx=5)

        self.dosya_kaydet_btn = ctk.CTkButton(self.file_frame, text="Sonucu Kaydet 💾", command=self.dosya_kaydet, 
                                              fg_color="white", text_color=self.vurgu_pembe, border_color=self.toz_pembe, border_width=2, hover_color="#fce4ec")
        self.dosya_kaydet_btn.grid(row=0, column=1, padx=5)

        # Metin Alanları
        self.input_text = ctk.CTkTextbox(self, width=450, height=120, border_color=self.toz_pembe, border_width=2, fg_color="white")
        self.input_text.pack(pady=10)

        self.pass_entry = ctk.CTkEntry(self, placeholder_text="Anahtar Şifre", show="*", width=450, border_color=self.toz_pembe, fg_color="white")
        self.pass_entry.pack(pady=10)

        # İşlem Butonları
        self.btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.btn_frame.pack(pady=15)

        ctk.CTkButton(self.btn_frame, text="Şifrele ✨", command=self.sifrele_islem, fg_color=self.buton_pembe, hover_color=self.vurgu_pembe).grid(row=0, column=0, padx=10)
        ctk.CTkButton(self.btn_frame, text="Çöz 🔓", command=self.coz_islem, fg_color=self.toz_pembe, text_color="white", hover_color=self.vurgu_pembe).grid(row=0, column=1, padx=10)

        self.output_text = ctk.CTkTextbox(self, width=450, height=120, border_color=self.toz_pembe, border_width=2, fg_color="white")
        self.output_text.pack(pady=10)

    # --- DOSYA İŞLEMLERİ ---

    def dosya_oku(self):
        dosya_yolu = filedialog.askopenfilename(filetypes=[("Metin Dosyaları", "*.txt"), ("Tüm Dosyalar", "*.*")])
        if dosya_yolu:
            try:
                with open(dosya_yolu, "r", encoding="utf-8") as f:
                    icerik = f.read()
                    self.input_text.delete("0.0", "end")
                    self.input_text.insert("0.0", icerik)
            except Exception as e:
                messagebox.showerror("Hata", f"Dosya okunamadı: {e}")

    def dosya_kaydet(self):
        icerik = self.output_text.get("0.0", "end-1c")
        if not icerik:
            messagebox.showwarning("Uyarı", "Kaydedilecek bir sonuç yok!")
            return
            
        dosya_yolu = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Metin Dosyaları", "*.txt")])
        if dosya_yolu:
            try:
                with open(dosya_yolu, "w", encoding="utf-8") as f:
                    f.write(icerik)
                messagebox.showinfo("Başarılı", "Dosya kaydedildi! 🌸")
            except Exception as e:
                messagebox.showerror("Hata", f"Dosya kaydedilemedi: {e}")

    # --- ŞİFRELEME / ÇÖZME İŞLEMLERİ ---

    def sifrele_islem(self):
        try:
            parola = self.pass_entry.get()
            if not parola:
                messagebox.showwarning("Uyarı", "Lütfen bir şifre girin! 🌸")
                return
            anahtar = anahtar_uret(parola)
            metin = self.input_text.get("0.0", "end-1c").encode('utf-8')
            sifreli = aes_sifrele(metin, anahtar)
            self.output_text.delete("0.0", "end")
            self.output_text.insert("0.0", sifreli.hex())
        except:
            messagebox.showerror("Hata", "Şifreleme başarısız.")

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