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
    "Pembe": {"sol_panel": "#FBCFE8", "sag_panel": "#FDF2F8", "buton_ana": "#EC4899", "buton_hover": "#BE185D", "yazi_koyu": "#831843", "yazi_acik": "#9D174D", "entry_bg": "#FFFFFF", "border": "#F472B6", "sidebar_btn": "#FFFFFF", "progress": "#EC4899"},
    "Buz Mavisi": {"sol_panel": "#BFDBFE", "sag_panel": "#EFF6FF", "buton_ana": "#3B82F6", "buton_hover": "#1D4ED8", "yazi_koyu": "#1E3A8A", "yazi_acik": "#1E40AF", "entry_bg": "#FFFFFF", "border": "#60A5FA", "sidebar_btn": "#FFFFFF", "progress": "#3B82F6"},
    "Açık Mor": {"sol_panel": "#DDD6FE", "sag_panel": "#F5F3FF", "buton_ana": "#8B5CF6", "buton_hover": "#6D28D9", "yazi_koyu": "#4C1D95", "yazi_acik": "#5B21B6", "entry_bg": "#FFFFFF", "border": "#A78BFA", "sidebar_btn": "#FFFFFF", "progress": "#8B5CF6"}
}

AYAR_DOSYASI = "ayarlar.json"

def ayar_yukle():
    if os.path.exists(AYAR_DOSYASI):
        try:
            with open(AYAR_DOSYASI, "r") as dosya:
                veri = json.load(dosya)
                return veri.get("tema", "Pembe")
        except: pass
    return "Pembe"

def ayar_kaydet(secilen_tema):
    with open(AYAR_DOSYASI, "w") as dosya:
        json.dump({"tema": secilen_tema}, dosya)

def anahtar_turet(parola, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480000)
    return base64.urlsafe_b64encode(kdf.derive(parola.encode()))