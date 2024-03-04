import pefile
import requests
import math
import tkinter as tk
from tkinter import messagebox, filedialog

red = "\033[1;31m"
green = "\033[1;32m"
purple = "\033[1;35m"
blue = "\033[1;34m"
reset = "\033[0;m"
yellow = "\033[1;33m"

def title():
    print("\nPE2H4x v1.0 Copyright <C> 2024-2025 0x1v4n")
    print("Lasted Version and Source Code: enlace\n")

def get_section_raw_size(exe, section_name):
    pe = pefile.PE(exe)
    for section in pe.sections:
        if section.Name.decode().strip('\x00') == section_name:
            return section.SizeOfRawData
    return exe, section_name

def get_entropy(exe):
    try:
        with open(exe, 'rb') as f:
            exe_bytes = f.read()
    except FileNotFoundError:
        messagebox.showerror("Error", "The specified file is invalid.")
        return None

    possible = dict(((chr(x), 0) for x in range(0, 256)))

    for byte in exe_bytes: 
        possible[chr(byte)] += 1

    data_len = len(exe_bytes)
    entropy = 0.0

    for i in possible:
        if possible[i] == 0:
            continue

        p = float(possible[i] / data_len)
        entropy -= p * math.log(p, 2)
    return entropy

def get_info_pe():
    exe = entry_exe.get()
    if not exe:
        messagebox.showerror("Error", "Please select an executable file.")
        return

    pe = pefile.PE(exe)
    name = exe
    imphash = pe.get_imphash()
    image_base = hex(pe.OPTIONAL_HEADER.ImageBase)
    EP = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    RVA = hex(pe.OPTIONAL_HEADER.NumberOfRvaAndSizes)
    sections = hex(pe.FILE_HEADER.NumberOfSections)
    section_name = ".text"
    if imphash == None:
        messagebox.showwarning("Warning", "The archive does not contain Immphash")
    else:
        entry_imphash.delete(0, tk.END)
        entry_imphash.insert(0, imphash)
        info = f"Name: {name}\nImphash: {imphash}\nImage Base: {image_base}\nEntry point: {EP}\nVirtual Address: {RVA}\nSections: {sections}\nSize of Raw Data: {hex(get_section_raw_size(exe, section_name))}"
        text_output.delete('1.0', tk.END)
        text_output.insert(tk.END, info)
        entropy = get_entropy(exe)
        if entropy is not None:
            if entropy < 7:
                messagebox.showinfo("Entropy", f"Entropy: {entropy} => Seems not to be obfuscated\n")
            elif entropy > 7:
                messagebox.showinfo("Entropy", f"Entropy: {entropy} => It seems to be obfuscated, try Detect it Easy(DIE) or PEiD!\n") 
            else:
                messagebox.showerror("Error", "Error calculating entropy.")
        else:
            messagebox.showerror("Error", "Error calculating entropy.")

def get_mal_info():
    imphash = entry_imphash.get()
    if not imphash:
        messagebox.showerror("Error", "Please enter an imphash.")
        return

    info = {'query': 'get_imphash', 'imphash': imphash, 'limit': '1'}
    response = requests.post("https://mb-api.abuse.ch/api/v1/", data=info)
    data = response.json()

    if data['query_status'] == 'ok':
        malware_data = data["data"][0]
        info = f"Name: {malware_data['file_name']}\nSize: {malware_data['file_size']}\nFirst seen: {malware_data['first_seen']}\nFile type: {malware_data['file_type']}\nSHA256 Hash: {malware_data['sha256_hash']}\nSHA3_384 Hash: {malware_data['sha3_384_hash']}\nSHA1 Hash: {malware_data['sha1_hash']}\nMD5 Hash: {malware_data['md5_hash']}\nSignature: {malware_data['signature']}\nTags: {malware_data['tags']}\nIntelligence: {malware_data['intelligence']}"
        groupbox_mal_info_output.config(text="Malware Info:")
        text_mal_info_output.delete('1.0', tk.END)
        text_mal_info_output.insert(tk.END, info)
    else:
        messagebox.showerror("Error", "Error getting malware info.")

def browse_file():
    filename = filedialog.askopenfilename(title="Select an executable file")
    entry_exe.delete(0, tk.END)
    entry_exe.insert(0, filename)

root = tk.Tk()
root.title("PE2H4x v1.0")

label_exe = tk.Label(root, text="Select an executable file:")
entry_exe = tk.Entry(root, width=50)
button_browse = tk.Button(root, text="Browse", command=browse_file)
button_info_pe = tk.Button(root, text="Get PE Info", command=get_info_pe)

groupbox_output = tk.LabelFrame(root, text="PE Info:")
text_output = tk.Text(groupbox_output, width=100, height=10)
scrollbar_output = tk.Scrollbar(groupbox_output, orient=tk.VERTICAL, command=text_output.yview)
text_output.config(yscrollcommand=scrollbar_output.set)

label_imphash = tk.Label(root, text="Imphash:")
entry_imphash = tk.Entry(root, width=50)
button_mal_info = tk.Button(root, text="Get Malware Info", command=get_mal_info)

groupbox_mal_info_output = tk.LabelFrame(root, text="Malware Info:")
text_mal_info_output = tk.Text(groupbox_mal_info_output, width=100, height=10)
scrollbar_mal_info_output = tk.Scrollbar(groupbox_mal_info_output, orient=tk.VERTICAL, command=text_mal_info_output.yview)
text_mal_info_output.config(yscrollcommand=scrollbar_mal_info_output.set)


label_exe.grid(row=0, column=0, padx=5, pady=5)
entry_exe.grid(row=0, column=1, padx=5, pady=5)
button_browse.grid(row=0, column=2, padx=5, pady=5)
button_info_pe.grid(row=0, column=3, padx=5, pady=5)

groupbox_output.grid(row=1, column=0, columnspan=4, padx=5, pady=5, sticky="nsew")
text_output.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")
scrollbar_output.grid(row=0, column=1, padx=0, pady=5, sticky="ns")

label_imphash.grid(row=2, column=0, padx=5, pady=5)
entry_imphash.grid(row=2, column=1, padx=5, pady=5)
button_mal_info.grid(row=2, column=2, padx=5, pady=5)

groupbox_mal_info_output.grid(row=3, column=0, columnspan=4, padx=5, pady=5, sticky="nsew")
text_mal_info_output.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")
scrollbar_mal_info_output.grid(row=0, column=1, padx=0, pady=5, sticky="ns")


root.grid_rowconfigure(1, weight=1)
root.grid_columnconfigure(0, weight=1)

root.mainloop()
