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

root = SifrelemeArayuzu()
root.title("CIPHER PRO | Aesthetic Edition")
root.geometry("850x650")

ana_font = ("Product Sans", 14)
baslik_font = ("Product Sans", 24, "bold")

try:
    pywinstyles.apply_style(root, "acrylic")
except:
    pass

dosya_yolu_var = ctk.StringVar()

root.grid_columnconfigure(1, weight=1)
root.grid_rowconfigure(0, weight=1)

sidebar = ctk.CTkFrame(root, width=220, corner_radius=20)
sidebar.grid(row=0, column=0, padx=15, pady=15, sticky="nsew")

baslik_sol = ctk.CTkLabel(sidebar, text="KORUMA\nMERKEZİ", font=ctk.CTkFont(family=ana_font[0], size=18, weight="bold"))
baslik_sol.pack(pady=(30, 20))

btn_foto = ctk.CTkButton(sidebar, text="FOTOĞRAF GİZLE", command=lambda: dosya_sec("foto"), corner_radius=15, font=ctk.CTkFont(family=ana_font[0], weight="bold"))
btn_foto.pack(pady=7, padx=20, fill="x")

btn_belge = ctk.CTkButton(sidebar, text="BELGE GİZLE", command=lambda: dosya_sec("belge"), corner_radius=15, font=ctk.CTkFont(family=ana_font[0], weight="bold"))
btn_belge.pack(pady=7, padx=20, fill="x")

btn_video = ctk.CTkButton(sidebar, text="VİDEO GİZLE", command=lambda: dosya_sec("video"), corner_radius=15, font=ctk.CTkFont(family=ana_font[0], weight="bold"))
btn_video.pack(pady=7, padx=20, fill="x")

btn_hepsi = ctk.CTkButton(sidebar, text="TÜM DOSYALAR", command=lambda: dosya_sec("hepsi"), corner_radius=15, font=ctk.CTkFont(family=ana_font[0], weight="bold"))
btn_hepsi.pack(pady=7, padx=20, fill="x")

ctk.CTkFrame(sidebar, height=2, fg_color="#FFFFFF").pack(fill="x", padx=25, pady=15)

tema_secici = ctk.CTkOptionMenu(sidebar, values=["Pembe", "Buz Mavisi", "Açık Mor"], command=tema_degistir, corner_radius=10, font=ctk.CTkFont(family=ana_font[0]))
tema_secici.pack(pady=7, padx=20, fill="x")

btn_anahtar = ctk.CTkButton(sidebar, text="ANAHTAR ÜRET", command=anahtar_olustur, corner_radius=15, font=ctk.CTkFont(family=ana_font[0], weight="bold"))
btn_anahtar.pack(pady=7, padx=20, fill="x")

btn_temizle = ctk.CTkButton(sidebar, text="TEMİZLE", command=lambda: [dosya_yolu_var.set(""), entry_path.delete(0, 'end'), sifre_entry.delete(0, 'end'), textbox_giris.delete("1.0", "end"), textbox_cikis.delete("1.0", "end")], corner_radius=15, font=ctk.CTkFont(family=ana_font[0], weight="bold"))
btn_temizle.pack(pady=7, padx=20, fill="x")

main_frame = ctk.CTkFrame(root, corner_radius=20)
main_frame.grid(row=0, column=1, padx=(0, 15), pady=15, sticky="nsew")

baslik_sag = ctk.CTkLabel(main_frame, text="VERİ ŞİFRELEME PANELİ", font=ctk.CTkFont(family=baslik_font[0], size=24, weight="bold"))
baslik_sag.pack(pady=(20, 10))

label_sifre = ctk.CTkLabel(main_frame, text="GİZLİ ŞİFRE", font=ctk.CTkFont(family=ana_font[0], size=14, weight="bold"))
label_sifre.pack(pady=(5, 5))

sifre_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
sifre_frame.pack(pady=5)

sifre_entry = ctk.CTkEntry(sifre_frame, width=300, height=45, corner_radius=20, show="●", justify="center", border_width=2, font=ctk.CTkFont(size=20))
sifre_entry.pack(side="left", padx=(30, 0))

btn_goster = ctk.CTkButton(sifre_frame, text="Göster", command=sifre_goster_gizle, width=30, height=30, fg_color="transparent", hover_color="#E2E8F0", font=ctk.CTkFont(family=ana_font[0], size=12, underline=True))
btn_goster.pack(side="left", padx=10)

sekme_kontrol = ctk.CTkTabview(main_frame, width=500, height=280, corner_radius=15)
sekme_kontrol.pack(pady=10, padx=20, fill="both", expand=True)

sekme_dosya = sekme_kontrol.add("Dosya Gizle")
sekme_metin = sekme_kontrol.add("Metin Gizle")

entry_path = ctk.CTkEntry(sekme_dosya, width=400, height=40, corner_radius=15, border_width=2, font=ctk.CTkFont(family=ana_font[0], size=12), placeholder_text="Dosya yolu veya dosyayı buraya sürükleyin...")
entry_path.pack(pady=10)
entry_path.drop_target_register(DND_FILES)
entry_path.dnd_bind('<<Drop>>', surukle_birak_al)

switch_sil = ctk.CTkSwitch(sekme_dosya, text="İşlemden Sonra Orijinal Dosyayı Sil", font=ctk.CTkFont(family=ana_font[0], size=12))
switch_sil.pack(pady=5)

ilerleme_frame = ctk.CTkFrame(sekme_dosya, fg_color="transparent", width=300, height=15)
ilerleme_frame.pack_propagate(False)
ilerleme_frame.pack(pady=(5, 5))

ilerleme_cubugu = ctk.CTkProgressBar(ilerleme_frame, mode="indeterminate", width=300, height=8, corner_radius=5)

btn_frame_dosya = ctk.CTkFrame(sekme_dosya, fg_color="transparent")
btn_frame_dosya.pack(pady=5)

btn_sifrele = ctk.CTkButton(btn_frame_dosya, text="ŞİFRELE", command=lambda: islem_yap("sifrele"), width=130, height=40, corner_radius=20, font=ctk.CTkFont(family=ana_font[0], weight="bold", size=14))
btn_sifrele.grid(row=0, column=0, padx=10)

btn_coz = ctk.CTkButton(btn_frame_dosya, text="ÇÖZ", command=lambda: islem_yap("coz"), width=130, height=40, corner_radius=20, font=ctk.CTkFont(family=ana_font[0], weight="bold", size=14))
btn_coz.grid(row=0, column=1, padx=10)

ctk.CTkLabel(sekme_metin, text="Giriş Metni:", font=ctk.CTkFont(family=ana_font[0], size=12, weight="bold")).pack(anchor="w", padx=30)
textbox_giris = ctk.CTkTextbox(sekme_metin, height=60, border_width=2, corner_radius=10, font=ctk.CTkFont(family=ana_font[0], size=13))
textbox_giris.pack(pady=2, padx=30, fill="x")

btn_frame_metin = ctk.CTkFrame(sekme_metin, fg_color="transparent")
btn_frame_metin.pack(pady=5)

btn_metin_sifrele = ctk.CTkButton(btn_frame_metin, text="METNİ ŞİFRELE", command=lambda: metin_islemi_yap("sifrele"), width=120, height=35, corner_radius=15, font=ctk.CTkFont(family=ana_font[0], weight="bold", size=12))
btn_metin_sifrele.grid(row=0, column=0, padx=10)

btn_metin_coz = ctk.CTkButton(btn_frame_metin, text="METNİ ÇÖZ", command=lambda: metin_islemi_yap("coz"), width=120, height=35, corner_radius=15, font=ctk.CTkFont(family=ana_font[0], weight="bold", size=12))
btn_metin_coz.grid(row=0, column=1, padx=10)

ctk.CTkLabel(sekme_metin, text="Şifrelenmiş Sonuç:", font=ctk.CTkFont(family=ana_font[0], size=12, weight="bold")).pack(anchor="w", padx=30)
textbox_cikis = ctk.CTkTextbox(sekme_metin, height=60, border_width=2, corner_radius=10, font=ctk.CTkFont(family=ana_font[0], size=13))
textbox_cikis.pack(pady=2, padx=30, fill="x")

btn_kopyala = ctk.CTkButton(sekme_metin, text="Sonucu Kopyala", command=metni_kopyala, height=25, corner_radius=10, font=ctk.CTkFont(family=ana_font[0], weight="bold", size=11))
btn_kopyala.pack(pady=5)

durum_etiketi = ctk.CTkLabel(main_frame, text="SİSTEM HAZIR", font=ctk.CTkFont(family=ana_font[0], size=12, slant="italic"))
durum_etiketi.pack(side="bottom", pady=10)

kayitli_tema = ayar_yukle()
tema_secici.set(kayitli_tema)
tema_degistir(kayitli_tema)

root.mainloop()
