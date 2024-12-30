import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
import numpy as np
import cv2

main_window = tk.Tk()
main_window.geometry("600x400")
main_window.title("Main Window - Image Encryption Decryption")

panelA = None
panelB = None
image_encrypted = None

def open_encryption_window():
    enc_window = tk.Toplevel(main_window)
    enc_window.geometry("1000x700")
    enc_window.title("Encryption")

    global panelA, panelB
    panelA = None
    panelB = None

    def open_img():
        global x, panelA, panelB
        x = filedialog.askopenfilename(title='Open Image')
        if not x:
            return
        img = Image.open(x)
        img = ImageTk.PhotoImage(img)
        if panelA is None:
            panelA = tk.Label(enc_window, image=img)
            panelA.image = img
            panelA.pack(side="left", padx=10, pady=10)
        if panelB is None:
            panelB = tk.Label(enc_window, image=img)
            panelB.image = img
            panelB.pack(side="right", padx=10, pady=10)
        else:
            panelA.configure(image=img)
            panelA.image = img
            panelB.configure(image=img)
            panelB.image = img

    def en_fun():
        global image_encrypted
        if x is None:
            messagebox.showwarning("No Image", "Please select an image to encrypt.")
            return
        
        image_input = cv2.imread(x, cv2.IMREAD_COLOR)
        key = np.random.randint(0, 256, size=image_input.shape, dtype=np.uint8)

        image_encrypted = cv2.bitwise_xor(image_input, key)

        key_save_path = filedialog.asksaveasfilename(
            title="Save Key",
            defaultextension=".npy",
            filetypes=[("NumPy files", "*.npy"), ("All files", "*.*")]
        )

        if key_save_path:
            np.save(key_save_path, key)
        else:
            messagebox.showinfo("Save Canceled", "The key save operation was canceled.")
            return

        save_path = filedialog.asksaveasfilename(
            title="Save Encrypted Image",
            defaultextension=".png",
            filetypes=[("PNG files", "*.png"), ("All files", "*.*")]
        )

        if save_path:
            cv2.imwrite(save_path, image_encrypted)

            imge = Image.open(save_path)
            imge = ImageTk.PhotoImage(imge)
            panelB.configure(image=imge)
            panelB.image = imge
            messagebox.showinfo("Encrypt Status", "Image encrypted and saved successfully.")
        else:
            messagebox.showinfo("Save Canceled", "The save operation was canceled.")

    chooseb = tk.Button(enc_window, text="Choose Image", command=open_img, font=("Arial", 20), bg="orange", fg="blue", borderwidth=3, relief="raised")
    chooseb.pack(pady=20)

    enb = tk.Button(enc_window, text="Encrypt", command=en_fun, font=("Arial", 20), bg="light green", fg="blue", borderwidth=3, relief="raised")
    enb.pack(pady=20)

def open_decryption_window():
    dec_window = tk.Toplevel(main_window)
    dec_window.geometry("1000x700")
    dec_window.title("Decryption")

    global panelB
    panelB = None
    global encrypted_image_path, key_path
    encrypted_image_path = None
    key_path = None

    def choose_image():
        global encrypted_image_path
        encrypted_image_path = filedialog.askopenfilename(
            title="Select Encrypted Image",
            filetypes=[("PNG files", "*.png"), ("All files", "*.*")]
        )
        if not encrypted_image_path:
            messagebox.showwarning("No Image", "No encrypted image selected.")

    def choose_key():
        global key_path
        key_path = filedialog.askopenfilename(
            title="Select Key File",
            filetypes=[("NumPy files", "*.npy"), ("All files", "*.*")]
        )
        if not key_path:
            messagebox.showwarning("No Key", "No key file selected.")

    def de_fun():
        global panelB
        global encrypted_image_path, key_path

        if not encrypted_image_path or not key_path:
            messagebox.showwarning("Missing Files", "Please select both the encrypted image and the key.")
            return

        try:
            key = np.load(key_path)
            encrypted_image = cv2.imread(encrypted_image_path, cv2.IMREAD_COLOR)

            image_output = cv2.bitwise_xor(encrypted_image, key)

            output_path = filedialog.asksaveasfilename(
                title="Save Decrypted Image",
                defaultextension=".png",
                filetypes=[("PNG files", "*.png"), ("All files", "*.*")]
            )

            if output_path:
                cv2.imwrite(output_path, image_output)

                imgd = Image.open(output_path)
                imgd = ImageTk.PhotoImage(imgd)
                if panelB is None:
                    panelB = tk.Label(dec_window, image=imgd)
                    panelB.image = imgd
                    panelB.pack(side="right", padx=10, pady=10)
                else:
                    panelB.configure(image=imgd)
                    panelB.image = imgd

                messagebox.showinfo("Decrypt Status", "Image decrypted successfully.")
            else:
                messagebox.showinfo("Save Canceled", "The save operation was canceled.")
        except Exception as e:
            messagebox.showerror("Decryption Error", f"An error occurred: {e}")

    choose_img_btn = tk.Button(dec_window, text="Choose Encrypted Image", command=choose_image, font=("Arial", 20), bg="orange", fg="blue", borderwidth=3, relief="raised")
    choose_img_btn.pack(pady=20)

    choose_key_btn = tk.Button(dec_window, text="Choose Key File", command=choose_key, font=("Arial", 20), bg="orange", fg="blue", borderwidth=3, relief="raised")
    choose_key_btn.pack(pady=20)

    decb = tk.Button(dec_window, text="Decrypt", command=de_fun, font=("Arial", 20), bg="light green", fg="blue", borderwidth=3, relief="raised")
    decb.pack(pady=20)

encryption_button = tk.Button(main_window, text="Encryption", command=open_encryption_window, font=("Arial", 20), bg="light green", fg="blue", borderwidth=3, relief="raised")
encryption_button.pack(pady=20)

decryption_button = tk.Button(main_window, text="Decryption", command=open_decryption_window, font=("Arial", 20), bg="light green", fg="blue", borderwidth=3, relief="raised")
decryption_button.pack(pady=20)

def exit_app():
    if messagebox.askokcancel("Exit", "Do you want to exit?"):
        main_window.destroy()

exit_button = tk.Button(main_window, text="EXIT", command=exit_app, font=("Arial", 20), bg="red", fg="blue", borderwidth=3, relief="raised")
exit_button.pack(pady=20)

main_window.protocol("WM_DELETE_WINDOW", exit_app)
main_window.mainloop()
