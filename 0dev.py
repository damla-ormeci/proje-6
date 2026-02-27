# --- GEREKLİ KÜTÜPHANELER ---
import tkinter as tk  # Kullanıcı arayüzünü (pencere, buton vb.) oluşturmak için[cite: 50].
from tkinter import filedialog, messagebox  # Dosya seçme penceresi ve uyarı mesajları için.
import base64  # Oluşturulan anahtarı uygun formata (URL safe) çevirmek için.
import os  # Bilgisayardaki dosya yollarına erişmek ve rastgele sayı (salt) üretmek için.

# Kriptografi kütüphanesi: AES algoritması ve anahtar türetme fonksiyonları buradan gelir[cite: 26, 47].
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

# --- GÜVENLİK VE ŞİFRELEME MANTIĞI ---

def anahtar_turet(parola: str, salt: bytes):
    """
    Kullanıcının girdiği basit parolayı AES için güçlü bir anahtara dönüştürür.
    Raporunuzda bahsedilen 'zayıf parola' sorununu PBKDF2 kullanarak çözer[cite: 30, 49].
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # Güvenli özetleme algoritması.
        length=32,  # AES-256 için 32 byte'lık anahtar üretir.
        salt=salt,  # Her şifrelemede değişen, anahtarı benzersiz yapan 'tuz'[cite: 49].
        iterations=480000,  # Parolayı kırmak isteyenlere karşı yavaşlatma/zorlaştırma işlemi.
    )
    # Parolayı karmaşık bir anahtara dönüştürür ve base64 formatında paketler.
    anahtar = base64.urlsafe_b64encode(kdf.derive(parola.encode()))
    return anahtar

def islem_yap(mod):
    """
    Arayüzdeki butonlara basıldığında çalışan ana fonksiyondur.
    'sifrele' veya 'coz' moduna göre hareket eder[cite: 31, 33].
    """
    dosya_yolu = dosya_yolu_var.get()  # Kutudaki dosya adresini alır.
    parola = sifre_entry.get()  # Kullanıcının yazdığı şifreyi alır[cite: 29].

    # Gerekli bilgiler boşsa kullanıcıyı uyarır[cite: 42].
    if not dosya_yolu or not parola:
        messagebox.showwarning("Uyarı", "Lütfen bir dosya seçin ve parola girin!")
        return

    try:
        if mod == "sifrele":
            # 1. Adım: Rastgele bir 'salt' (tuz) oluşturur.
            salt = os.urandom(16)
            # 2. Adım: Paroladan AES anahtarını türetir[cite: 30].
            anahtar = anahtar_turet(parola, salt)
            f = Fernet(anahtar)
            
            # 3. Adım: Orijinal dosyayı ikili (binary) modda okur[cite: 28].
            with open(dosya_yolu, "rb") as file:
                veri = file.read()
            
            # 4. Adım: Veriyi AES ile şifreler[cite: 31].
            sifreli_veri = f.encrypt(veri)
            
            # 5. Adım: .cipher uzantılı yeni dosya oluşturur[cite: 32].
            yeni_dosya = dosya_yolu + ".cipher"
            with open(yeni_dosya, "wb") as file:
                # Dosyanın başına tuzu ekleriz ki geri çözerken kullanabilelim.
                file.write(salt + sifreli_veri)
            
            # Başarılı mesajını ekrana ve duruma yazar[cite: 42].
            durum_etiketi.config(text=f"DURUM: Şifrelendi ({os.path.basename(yeni_dosya)})", fg="green")
            messagebox.showinfo("Başarılı", "Dosya şifrelendi! Artık orijinali silebilirsiniz.")
            
        elif mod == "coz":
            # Sadece .cipher uzantılı dosyaları kabul eder.
            if not dosya_yolu.endswith(".cipher"):
                messagebox.showerror("Hata", "Lütfen '.cipher' uzantılı bir dosya seçin!")
                return

            with open(dosya_yolu, "rb") as file:
                icerik = file.read()
            
            # Dosyanın ilk 16 byte'ından tuzu, kalanından şifreli veriyi ayırır.
            salt = icerik[:16]
            sifreli_veri = icerik[16:]
            # Aynı tuz ve parola ile anahtarı tekrar oluşturur.
            anahtar = anahtar_turet(parola, salt)
            f = Fernet(anahtar)
            
            # Şifreyi çözer. Parola yanlışsa burası hata verir.
            cozulmus_veri = f.decrypt(sifreli_veri)
            # .cipher uzantısını kaldırarak orijinal ismi geri kazanır.
            yeni_ad = dosya_yolu.replace(".cipher", "")
            
            with open(yeni_ad, "wb") as file:
                file.write(cozulmus_veri)
            
            durum_etiketi.config(text=f"DURUM: Çözüldü ({os.path.basename(yeni_ad)})", fg="blue")
            messagebox.showinfo("Başarılı", "Şifre çözüldü! Dosyanız hazır.")

    except Exception:
        # Hata durumunda (Örn: Yanlış parola) kullanıcıyı bilgilendirir[cite: 42].
        durum_etiketi.config(text="DURUM: Hata Oluştu!", fg="red")
        messagebox.showerror("Hata", "İşlem başarısız! Parola yanlış olabilir.")

# --- ARAYÜZ (TKINTER) TASARIMI ---

def dosya_sec():
    """Windows/Mac dosya seçme penceresini açar[cite: 43]."""
    dosya = filedialog.askopenfilename()
    if dosya:
        dosya_yolu_var.set(dosya)  # Seçilen yolu kutuya yazar.
        durum_etiketi.config(text=f"Seçilen: {os.path.basename(dosya)}", fg="black")

# Ana pencere ayarları [cite: 50]
root = tk.Tk()
root.title("CipherFile - Tek Panel Yönetimi")
root.geometry("500x350")  # Pencere boyutu.

dosya_yolu_var = tk.StringVar()  # Dosya yolunu tutan değişken.

# Görsel Etiketler ve Butonlar (Kullanım kolaylığı odaklı) [cite: 39, 41]
tk.Label(root, text="CipherFile: Güvenli Dosya Yönetimi", font=("Arial", 14, "bold")).pack(pady=15)

# Dosya Seçme Bölümü
frame = tk.Frame(root)
frame.pack(pady=10)
tk.Entry(frame, textvariable=dosya_yolu_var, width=40).grid(row=0, column=0, padx=5)
tk.Button(frame, text="Dosya Seç", command=dosya_sec).grid(row=0, column=1)

# Parola Giriş Bölümü
tk.Label(root, text="İşlem Parolası:", font=("Arial", 10)).pack()
sifre_entry = tk.Entry(root, show="*", width=30, font=("Arial", 12))  # Yazılanı '*' olarak gizler.
sifre_entry.pack(pady=10)

# Şifreleme ve Çözme Butonları [cite: 40]
btn_frame = tk.Frame(root)
btn_frame.pack(pady=15)
# Yeşil buton: Şifrele.
tk.Button(btn_frame, text="ŞİFRELE", bg="#4CAF50", fg="white", width=15, 
          command=lambda: islem_yap("sifrele")).grid(row=0, column=0, padx=10)
# Kırmızı buton: Çöz.
tk.Button(btn_frame, text="ŞİFREYİ ÇÖZ", bg="#f44336", fg="white", width=15, 
          command=lambda: islem_yap("coz")).grid(row=0, column=1, padx=10)

# En alttaki durum çubuğu
durum_etiketi = tk.Label(root, text="DURUM: Hazır", font=("Arial", 10, "italic"))
durum_etiketi.pack(pady=20)

# Programı başlatan ve pencereyi açık tutan döngü.
root.mainloop()