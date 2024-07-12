import os
from tkinter import Tk, filedialog, simpledialog, messagebox, Button, Label
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

def encrypt_image(input_image_path, output_encrypted_path, key):
    with open(input_image_path, 'rb') as f:
        image_data = f.read()

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(image_data) + padder.finalize()

    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    with open(output_encrypted_path, 'wb') as f:
        f.write(iv + encrypted_data)

def decrypt_image(input_encrypted_path, output_decrypted_path, key):
    try:
        with open(input_encrypted_path, 'rb') as f:
            iv = f.read(16)
            encrypted_data = f.read()

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

        decryptor = cipher.decryptor()
        decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

        with open(output_decrypted_path, 'wb') as f:
            f.write(decrypted_data)
    except Exception as e:
        return False
    return True

def select_image_for_encryption():
    input_image_path = filedialog.askopenfilename(title="Select Image to Encrypt")
    if not input_image_path:
        return

    # key = simpledialog.askstring("Input Key", "Enter the encryption key (in hex format):")
    # key = os.urandom(32)
    key = simpledialog.askinteger("Input Key", "Enter the encryption key (integer):")
    if key is None:
        return

    key_bytes = key.to_bytes(16, byteorder='big')  # Convert integer key to bytes suitable for AES

    # try:
    #     key = bytes.fromhex(key)
    # except ValueError:
    #     messagebox.showerror("Invalid Key", "The key provided is not in the correct hex format.")
    #     return

    # output_encrypted_path = filedialog.asksaveasfilename(title="Save Encrypted Image As", defaultextension=".enc")
    output_encrypted_path = input_image_path
    if not output_encrypted_path:
        return

    encrypt_image(input_image_path, output_encrypted_path, key_bytes)
    messagebox.showinfo("Encryption Complete", f"Encryption complete.\nKey: {key}")
    print(f"Encryption complete.\nKey: {key}")

def select_image_for_decryption():
    input_encrypted_path = filedialog.askopenfilename(title="Select Encrypted Image")
    if not input_encrypted_path:
        return

    key = simpledialog.askinteger("Input Key", "Enter the encryption key (integer):")
    if not key:
        return

    key_bytes = key.to_bytes(16, byteorder='big')  # Convert integer key to bytes suitable for AES

    # output_decrypted_path = filedialog.asksaveasfilename(title="Save Decrypted Image As", defaultextension=".jpg")
    output_decrypted_path = input_encrypted_path
    if not output_decrypted_path:
        return

    if decrypt_image(input_encrypted_path, output_decrypted_path, key_bytes):
        messagebox.showinfo("Decryption Complete", "Decryption complete.")
    else:
        messagebox.showerror("Decryption Failed", "Decryption failed. The key may be incorrect.")

def main():
    root = Tk()
    root.title("Image Encryption/Decryption")

    label = Label(root, text="Select an option:")
    label.pack(pady=10)

    encrypt_button = Button(root, text="Encrypt Image", command=select_image_for_encryption)
    encrypt_button.pack(pady=5)

    decrypt_button = Button(root, text="Decrypt Image", command=select_image_for_decryption)
    decrypt_button.pack(pady=5)

    root.mainloop()

if __name__ == "__main__":
    main()
