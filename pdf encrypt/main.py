import tkinter as tk
from tkinter import filedialog, messagebox
import PyPDF2

def encrypt_pdf(input_pdf, output_pdf, password):
    """Encrypts a PDF file with the given password."""
    try:
        with open(input_pdf, 'rb') as pdf_file:
            reader = PyPDF2.PdfReader(pdf_file)
            writer = PyPDF2.PdfWriter()

            for page in reader.pages:
                writer.add_page(page)

            writer.encrypt(password)

            with open(output_pdf, 'wb') as encrypted_file:
                writer.write(encrypted_file)

        messagebox.showinfo("Success", f"PDF encrypted successfully and saved as:\n{output_pdf}")
    except Exception as e:
        messagebox.showerror("Error", f"Error encrypting PDF:\n{str(e)}")

def decrypt_pdf(input_pdf, output_pdf, password):
    """Decrypts a PDF file with the given password."""
    try:
        with open(input_pdf, 'rb') as pdf_file:
            reader = PyPDF2.PdfReader(pdf_file)

            if reader.is_encrypted:
                reader.decrypt(password)

            writer = PyPDF2.PdfWriter()

            for page in reader.pages:
                writer.add_page(page)

            with open(output_pdf, 'wb') as decrypted_file:
                writer.write(decrypted_file)

        messagebox.showinfo("Success", f"PDF decrypted successfully and saved as:\n{output_pdf}")
    except Exception as e:
        messagebox.showerror("Error", f"Error decrypting PDF:\n{str(e)}")

def select_input_file():
    """Opens a file dialog to select the input PDF file."""
    file_path = filedialog.askopenfilename(filetypes=[("PDF Files", "*.pdf")])
    input_file_entry.delete(0, tk.END)
    input_file_entry.insert(0, file_path)

def select_output_file():
    """Opens a file dialog to select the output PDF file."""
    file_path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF Files", "*.pdf")])
    output_file_entry.delete(0, tk.END)
    output_file_entry.insert(0, file_path)

def process_pdf(action):
    """Processes the PDF based on the selected action (encrypt or decrypt)."""
    input_file = input_file_entry.get()
    output_file = output_file_entry.get()
    password = password_entry.get()

    if not input_file or not output_file or not password:
        messagebox.showerror("Error", "All fields are required!")
        return

    if action == "encrypt":
        encrypt_pdf(input_file, output_file, password)
    elif action == "decrypt":
        decrypt_pdf(input_file, output_file, password)

# GUI Setup
root = tk.Tk()
root.title("PDF Encrypt and Decrypt Tool")
root.configure(bg="#d4f5d0")  # Light green background

# Styles
label_font = ("Arial", 12, "bold")
button_font = ("Arial", 10, "bold")
footer_font = ("Arial", 10, "italic")

# Header Label
tk.Label(root, text="PDF Encrypt and Decrypt Tool", font=("Arial", 16, "bold"), fg="white", bg="green", pady=10).grid(row=0, column=0, columnspan=3, sticky="nsew")

# Input PDF File
tk.Label(root, text="Input PDF File:", font=label_font, bg="#d4f5d0").grid(row=1, column=0, padx=10, pady=5, sticky=tk.W)
input_file_entry = tk.Entry(root, width=50)
input_file_entry.grid(row=1, column=1, padx=10, pady=5)
tk.Button(root, text="Browse", command=select_input_file, font=button_font, bg="green", fg="white").grid(row=1, column=2, padx=10, pady=5)

# Output PDF File
tk.Label(root, text="Output PDF File:", font=label_font, bg="#d4f5d0").grid(row=2, column=0, padx=10, pady=5, sticky=tk.W)
output_file_entry = tk.Entry(root, width=50)
output_file_entry.grid(row=2, column=1, padx=10, pady=5)
tk.Button(root, text="Browse", command=select_output_file, font=button_font, bg="green", fg="white").grid(row=2, column=2, padx=10, pady=5)

# Password
tk.Label(root, text="Password:", font=label_font, bg="#d4f5d0").grid(row=3, column=0, padx=10, pady=5, sticky=tk.W)
password_entry = tk.Entry(root, show="*", width=50)
password_entry.grid(row=3, column=1, padx=10, pady=5)

# Buttons for Encrypt and Decrypt
tk.Button(root, text="Encrypt PDF", command=lambda: process_pdf("encrypt"), font=button_font, bg="#4caf50", fg="white").grid(row=4, column=0, columnspan=1, pady=10, ipadx=10)
tk.Button(root, text="Decrypt PDF", command=lambda: process_pdf("decrypt"), font=button_font, bg="#2196f3", fg="white").grid(row=4, column=1, columnspan=2, pady=10, ipadx=10)

# Footer
footer = tk.Label(root, text="Made by TEAM CLICK2VOTE", font=footer_font, bg="green", fg="white", pady=10)
footer.grid(row=5, column=0, columnspan=3, sticky="nsew")

# Adjust column weights
root.grid_columnconfigure(0, weight=1)
root.grid_columnconfigure(1, weight=2)
root.grid_columnconfigure(2, weight=1)

# Run the GUI loop
root.mainloop()
