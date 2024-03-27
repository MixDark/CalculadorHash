import hashlib
import tkinter as tk
from tkinter import messagebox

class HashLogica:

    def calculate_hashes(self, clave):
        md5 = hashlib.md5(clave.encode('utf-8')).hexdigest()
        sha1 = hashlib.sha1(clave.encode('utf-8')).hexdigest()
        sha224 = hashlib.sha224(clave.encode('utf-8')).hexdigest()
        sha256 = hashlib.sha256(clave.encode('utf-8')).hexdigest()
        sha384 = hashlib.sha384(clave.encode('utf-8')).hexdigest()
        sha512 = hashlib.sha512(clave.encode('utf-8')).hexdigest()
        return md5, sha1, sha224, sha256, sha384, sha512

class HashGUI:
    
    def __init__(self, master):
        self.master = master
        self.master.title("Calculador de hash")

        #Tamaño fijo y ventana centrada
        self.master.resizable(0,0)
        self.ancho = 1220
        self.alto = 310
        self.ventana_x = master.winfo_screenwidth() // 2 - self.ancho // 2
        self.ventana_y = master.winfo_screenheight() // 2 - self.alto // 2
        posicion = str(self.ancho) + "x" + str(self.alto) + "+" + str(self.ventana_x) + "+" + str(self.ventana_y)
        self.master.geometry(posicion)

        self.label = tk.Label(self.master, text="Ingresa el texto a transformar en hash:", font=("Arial", 12))
        self.label.grid(row=0, column=0, columnspan=2, pady=5)

        self.entry = tk.Entry(self.master, width=80, font=("Arial", 12))
        self.entry.grid(row=1, column=0, columnspan=2, pady=5)

        self.button = tk.Button(self.master, text="Calcular hash", command=self.calculate_hash, font=("Arial", 12))
        self.button.grid(row=2, column=0, columnspan=2, pady=5)

        self.result_labels = ["MD5:", "SHA1:", "SHA224:", "SHA256:", "SHA384:", "SHA512:"]
        self.result_texts = []

        for i, label_text in enumerate(self.result_labels):
            label = tk.Label(self.master, text=label_text, font=("Arial", 12))
            label.grid(row=i + 3, column=0, padx=5, sticky="w")

            text_widget = tk.Text(self.master, height=1, width=124, font=("Arial", 12))
            text_widget.grid(row=i + 3, column=1, padx=5, pady=5)
            self.result_texts.append(text_widget)

    def calculate_hash(self):
        clave = self.entry.get()

        if clave:
            logic = HashLogica()
            md5, sha1, sha224, sha256, sha384, sha512 = logic.calculate_hashes(clave)

            self.result_texts[0].config(state="normal")
            self.result_texts[1].config(state="normal")
            self.result_texts[2].config(state="normal")
            self.result_texts[3].config(state="normal")
            self.result_texts[4].config(state="normal")
            self.result_texts[5].config(state="normal")

            # Actualizar los textos en las cajas de texto
            self.result_texts[0].delete("1.0", tk.END)
            self.result_texts[0].insert(tk.END, md5)
            self.result_texts[1].delete("1.0", tk.END)
            self.result_texts[1].insert(tk.END, sha1)
            self.result_texts[2].delete("1.0", tk.END)
            self.result_texts[2].insert(tk.END, sha224)
            self.result_texts[3].delete("1.0", tk.END)
            self.result_texts[3].insert(tk.END, sha256)
            self.result_texts[4].delete("1.0", tk.END)
            self.result_texts[4].insert(tk.END, sha384)
            self.result_texts[5].delete("1.0", tk.END)
            self.result_texts[5].insert(tk.END, sha512)

            self.result_texts[0].config(state="disable")
            self.result_texts[1].config(state="disable")
            self.result_texts[2].config(state="disable")
            self.result_texts[3].config(state="disable")
            self.result_texts[4].config(state="disable")
            self.result_texts[5].config(state="disable")


        else:
            messagebox.showerror("Error", "Por favor ingresa un texto")

def main():
    root = tk.Tk()
    app = HashGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
