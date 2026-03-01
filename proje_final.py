import customtkinter as ctk
import pywinstyles
from tkinter import filedialog, messagebox
import base64
import os
import json
import threading
import random
import string
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from tkinterdnd2 import TkinterDnD, DND_FILES

class SifrelemeArayuzu(ctk.CTk, TkinterDnD.DnDWrapper):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.TkdndVersion = TkinterDnD._require(self)

ctk.set_appearance_mode("light")

temalar = {
    "Pembe": {
        "sol_panel": "#FBCFE8", "sag_panel": "#FDF2F8", 
        "buton_ana": "#EC4899", "buton_hover": "#BE185D", 
        "yazi_koyu": "#831843", "yazi_acik": "#9D174D", 
        "entry_bg": "#FFFFFF", "border": "#F472B6", "sidebar_btn": "#FFFFFF", "progress": "#EC4899"
    },
    "Buz Mavisi": {
        "sol_panel": "#BFDBFE", "sag_panel": "#EFF6FF", 
        "buton_ana": "#3B82F6", "buton_hover": "#1D4ED8", 
        "yazi_koyu": "#1E3A8A", "yazi_acik": "#1E40AF", 
        "entry_bg": "#FFFFFF", "border": "#60A5FA", "sidebar_btn": "#FFFFFF", "progress": "#3B82F6"
    },
    "Açık Mor": {
        "sol_panel": "#DDD6FE", "sag_panel": "#F5F3FF", 
        "buton_ana": "#8B5CF6", "buton_hover": "#6D28D9", 
        "yazi_koyu": "#4C1D95", "yazi_acik": "#5B21B6", 
        "entry_bg": "#FFFFFF", "border": "#A78BFA", "sidebar_btn": "#FFFFFF", "progress": "#8B5CF6"
    }
}

AYAR_DOSYASI = "ayarlar.json"

def ayar_yukle():
    if os.path.exists(AYAR_DOSYASI):
        try:
            with open(AYAR_DOSYASI, "r") as dosya:
                veri = json.load(dosya)
                tema = veri.get("tema", "Pembe")
                if tema not in temalar:
                    return "Pembe"
                return tema
        except:
            pass
    return "Pembe"

def ayar_kaydet(secilen_tema):
    with open(AYAR_DOSYASI, "w") as dosya:
        json.dump({"tema": secilen_tema}, dosya)

def anahtar_turet(parola: str, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    return base64.urlsafe_b64encode(kdf.derive(parola.encode()))

def anahtar_olustur():
    sifre = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(16))
    sifre_entry.delete(0, 'end')
    sifre_entry.insert(0, sifre)

def islem_yap(mod):
    dosya_yolu = dosya_yolu_var.get()
    parola = sifre_entry.get()
    
    if not dosya_yolu or not parola:
        messagebox.showwarning("Uyarı", "Lütfen dosya seçin ve parola girin!")
        return

    btn_sifrele.configure(state="disabled")
    btn_coz.configure(state="disabled")
    durum_etiketi.configure(text="İşlem Devam Ediyor...")
    
    ilerleme_cubugu.pack(pady=3)
    ilerleme_cubugu.start()

    def arka_plan_islem():
        try:
            if mod == "sifrele":
                salt = os.urandom(16)
                anahtar = anahtar_turet(parola, salt)
                f = Fernet(anahtar)
                
                with open(dosya_yolu, "rb") as file:
                    veri = file.read()
                
                sifreli_veri = f.encrypt(veri)
                yeni_dosya = dosya_yolu + ".cipher"
                
                with open(yeni_dosya, "wb") as file:
                    file.write(salt + sifreli_veri)

                if switch_sil.get() == 1:
                    os.remove(dosya_yolu)

                root.after(0, islem_basarili, "Sistem Hazır - Şifrelendi", yeni_dosya)

            elif mod == "coz":
                with open(dosya_yolu, "rb") as file:
                    icerik = file.read()
                
                salt, sifreli_veri = icerik[:16], icerik[16:]
                anahtar = anahtar_turet(parola, salt)
                f = Fernet(anahtar)
                cozulmus_veri = f.decrypt(sifreli_veri)
                
                cikti_yolu = dosya_yolu.replace(".cipher", "")
                with open(cikti_yolu, "wb") as file:
                    file.write(cozulmus_veri)

                if switch_sil.get() == 1:
                    os.remove(dosya_yolu)

                root.after(0, islem_basarili, "Sistem Hazır - Çözüldü", cikti_yolu)

        except Exception:
            root.after(0, islem_hatali)

    threading.Thread(target=arka_plan_islem).start()


def metin_islemi_yap(mod):
    parola = sifre_entry.get()
    metin = textbox_giris.get("1.0", "end-1c").strip()
    
    if not parola or not metin:
        messagebox.showwarning("Uyarı", "Lütfen şifrelenecek/çözülecek metni ve parolayı girin!")
        return
        
    try:
        if mod == "sifrele":
            salt = os.urandom(16)
            anahtar = anahtar_turet(parola, salt)
            f = Fernet(anahtar)
            
            sifreli_byte = f.encrypt(metin.encode('utf-8'))
            
            tam_veri = base64.urlsafe_b64encode(salt + sifreli_byte).decode('utf-8')
            
            textbox_cikis.delete("1.0", "end")
            textbox_cikis.insert("1.0", tam_veri)
            durum_etiketi.configure(text="Sistem Hazır - Metin Şifrelendi")
            
        elif mod == "coz":
            
            tam_veri_byte = base64.urlsafe_b64decode(metin.encode('utf-8'))
            salt, sifreli_byte = tam_veri_byte[:16], tam_veri_byte[16:]
            
            anahtar = anahtar_turet(parola, salt)
            f = Fernet(anahtar)
            
            cozulmus_metin = f.decrypt(sifreli_byte).decode('utf-8')
            
            textbox_cikis.delete("1.0", "end")
            textbox_cikis.insert("1.0", cozulmus_metin)
            durum_etiketi.configure(text="Sistem Hazır - Metin Çözüldü")
            
    except Exception:
        messagebox.showerror("Hata", "Geçersiz parola veya hatalı şifrelenmiş metin!")

def metni_kopyala():
    
    alinacak_metin = textbox_cikis.get("1.0", "end-1c")
    if alinacak_metin:
        root.clipboard_clear()
        root.clipboard_append(alinacak_metin)
        durum_etiketi.configure(text="Sistem Hazır - Panoya Kopyalandı")

def islem_basarili(mesaj, yeni_yol):
    ilerleme_cubugu.stop()
    ilerleme_cubugu.pack_forget()
    btn_sifrele.configure(state="normal")
    btn_coz.configure(state="normal")
    durum_etiketi.configure(text=mesaj)
    dosya_yolu_var.set(yeni_yol)
    entry_path.delete(0, 'end')
    entry_path.insert(0, yeni_yol)

def islem_hatali():
    ilerleme_cubugu.stop()
    ilerleme_cubugu.pack_forget()
    btn_sifrele.configure(state="normal")
    btn_coz.configure(state="normal")
    durum_etiketi.configure(text="SİSTEM HAZIR")
    messagebox.showerror("Hata", "Geçersiz parola veya bozuk dosya!")

def dosya_sec(tur):
    tipler = [("Tüm Dosyalar", "*.*")]
    
    if tur == "foto":
        tipler = [("Resim Dosyaları", "*.png *.jpg *.jpeg *.gif *.bmp")]
    elif tur == "belge":
        tipler = [("Belgeler", "*.pdf *.docx *.txt *.xlsx *.pptx")]
    elif tur == "video":
        tipler = [("Videolar", "*.mp4 *.avi *.mkv *.mov")]

    dosya = filedialog.askopenfilename(filetypes=tipler)
    if dosya:
        dosya_yolu_var.set(dosya)
        entry_path.delete(0, 'end')
        entry_path.insert(0, dosya)

def surukle_birak_al(event):
    dosya = event.data.strip("{}")
    dosya_yolu_var.set(dosya)
    entry_path.delete(0, 'end')
    entry_path.insert(0, dosya)

def sifre_goster_gizle():
    if sifre_entry.cget("show") == "●":
        sifre_entry.configure(show="")
        btn_goster.configure(text="Gizle")
    else:
        sifre_entry.configure(show="●")
        btn_goster.configure(text="Göster")

def tema_degistir(secilen):
    renk = temalar[secilen]
    
    sidebar.configure(fg_color=renk["sol_panel"])
    main_frame.configure(fg_color=renk["sag_panel"])
    
    baslik_sol.configure(text_color=renk["yazi_koyu"])
    baslik_sag.configure(text_color=renk["yazi_koyu"])
    
    for btn in [btn_foto, btn_belge, btn_video, btn_hepsi, btn_anahtar, btn_temizle]:
        btn.configure(fg_color=renk["sidebar_btn"], text_color=renk["yazi_koyu"], hover_color=renk["sag_panel"])
        
    entry_path.configure(fg_color=renk["entry_bg"], text_color=renk["yazi_koyu"], border_color=renk["border"])
    sifre_entry.configure(fg_color=renk["entry_bg"], text_color=renk["yazi_koyu"], border_color=renk["border"])
    
    # Yeni eklediğim metin kutularının renklerini de güncelliyorum.
    textbox_giris.configure(fg_color=renk["entry_bg"], text_color=renk["yazi_koyu"], border_color=renk["border"])
    textbox_cikis.configure(fg_color=renk["entry_bg"], text_color=renk["yazi_koyu"], border_color=renk["border"])
    
    for btn in [btn_sifrele, btn_coz, btn_metin_sifrele, btn_metin_coz, btn_kopyala]:
        btn.configure(fg_color=renk["buton_ana"], hover_color=renk["buton_hover"], text_color="#FFFFFF")
    
    sekme_kontrol.configure(segmented_button_selected_color=renk["buton_ana"], segmented_button_selected_hover_color=renk["buton_hover"], text_color=renk["yazi_koyu"])
    switch_sil.configure(progress_color=renk["buton_ana"], text_color=renk["yazi_koyu"])
    durum_etiketi.configure(text_color=renk["yazi_acik"])
    label_sifre.configure(text_color=renk["yazi_koyu"])
    btn_goster.configure(text_color=renk["yazi_koyu"])
    
    ilerleme_cubugu.configure(progress_color=renk["progress"])
    
    ayar_kaydet(secilen)
