import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
import hashlib, base64

class OptimizedCipher:
    def __init__(self, master):
        self.master = master
        master.title("NanoCrypt 2026")
        master.geometry("380x300")
        master.config(padx=20, pady=20)

        # UI Elemanları
        tk.Label(master, text="Anahtar Kelime:", font=('Arial', 10, 'bold')).pack(anchor="w")
        self.key_entry = tk.Entry(master, show="*", width=40)
        self.key_entry.pack(pady=5)

        tk.Button(master, text="📁 Dosya Seç ve Şifrele", width=30, bg="#e1f5fe", command=lambda: self.process(True)).pack(pady=10)
        tk.Button(master, text="🔓 Dosya Seç ve Çöz", width=30, bg="#f1f8e9", command=lambda: self.process(False)).pack(pady=5)
        
        self.status = tk.Label(master, text="Hazır", fg="grey")
        self.status.pack(side="bottom")

    def get_fernet(self):
        # Parolayı güvenli 32-byte Fernet anahtarına dönüştürür
        h = hashlib.sha256(self.key_entry.get().encode()).digest()
        return Fernet(base64.urlsafe_b64encode(h))

    def process(self, encrypt=True):
        path = filedialog.askopenfilename()
        if not path or not self.key_entry.get(): return
        
        try:
            f = self.get_fernet()
            with open(path, "rb") as file:
                data = file.read()
            
            output = f.encrypt(data) if encrypt else f.decrypt(data)
            
            with open(path, "wb") as file:
                file.write(output)
            
            self.status.config(text="İşlem Başarılı!", fg="green")
            messagebox.showinfo("Başarılı", "Dosya güncellendi.")
        except Exception as e:
            messagebox.showerror("Hata", "Şifre yanlış veya dosya bozuk!")

if __name__ == "__main__":
    root = tk.Tk()
    app = OptimizedCipher(root)
    root.mainloop()
