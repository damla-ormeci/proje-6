import tkinter as tk
from tkinter import filedialog, messagebox
import base64
	
def basit_islem(mod):
    sifre = sifre_entry.get()
    veri = metin_alanı.get("1.0", tk.END).strip()
    if not sifre or not veri: return
    
    # Basit bir XOR veya Base64 mantığı
    if mod == "sifrele":
        encoded = base64.b64encode(veri.encode()).decode()
        sonuc_alanı.delete("1.0", tk.END); sonuc_alanı.insert(tk.END, encoded)
    else:
        try:
            decoded = base64.b64decode(veri.encode()).decode()
            sonuc_alanı.delete("1.0", tk.END); sonuc_alanı.insert(tk.END, decoded)
        except: messagebox.showerror("Hata", "Geçersiz veri!")

root = tk.Tk()
root.title("İlkel Şifreleyici")
metin_alanı = tk.Text(root, height=5); metin_alanı.pack()
sifre_entry = tk.Entry(root, show="*"); sifre_entry.pack()
tk.Button(root, text="Şifrele", command=lambda: basit_islem("sifrele")).pack()
tk.Button(root, text="Çöz", command=lambda: basit_islem("coz")).pack()
sonuc_alanı = tk.Text(root, height=5); sonuc_alanı.pack()
root.mainloop()

