import pefile
import requests
import math


red = "\033[1;31m"
green = "\033[1;32m"
purple = "\033[1;35m"
blue = "\033[1;34m"
reset = "\033[0;m"
yellow = "\033[1;33m"

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
        print("The specified file is invalid.")
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
    exe = input("Select an executable file: ")
    pe = pefile.PE(exe)
    name = exe
    imphash = pe.get_imphash()
    image_base = hex(pe.OPTIONAL_HEADER.ImageBase)
    EP = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    RVA = hex(pe.OPTIONAL_HEADER.NumberOfRvaAndSizes)
    sections = hex(pe.FILE_HEADER.NumberOfSections)
    section_name = ".text"
    if imphash == None:
        print("The archive does not contain Imphash")
    else:
        print("Name:",name)
        print("Imphash:",imphash)
        print("Image Base:",image_base)
        print("Entry point:",EP)
        print("Virtual Address:",RVA)
        print("Sections:",sections)
        print("Size of Raw Data:",hex(get_section_raw_size(exe,section_name)))
        entropy = get_entropy(exe)
        if entropy is not None:
            if entropy < 7:
                print("Entropy:",entropy,yellow,"=> Seems not to be obfuscated\n",reset)
            elif entropy > 7:
                print("Entropy:",entropy,red,"It seems to be obfuscated, try Detect it Easy(DIE) or PEiD!\n",reset) 
            else:
                print("Error.")
        else:
            print("Entropy could not be calculated.")

    return exe,name,imphash,image_base,RVA,EP,sections


def get_mal_info(exe):
    info =  {'query': 'get_imphash', 'imphash': exe, 'limit': '1'}
    response = requests.post("https://mb-api.abuse.ch/api/v1/", data=info)
    data = response.json()

    if data['query_status'] == 'ok':
        print(yellow,">> Analysing executable...\n",reset)
        malware_data = data["data"][0]
        print("Name:",malware_data["file_name"])
        print("Size:",malware_data["file_size"])
        print("First seen:",malware_data["first_seen"])
        print("File type:",malware_data["file_type"])
        print("SHA256 Hash:",malware_data["sha256_hash"])
        print("SHA3_384 Hash:",malware_data["sha3_384_hash"])
        print("SHA1 Hash:",malware_data["sha1_hash"])
        print("MD5 Hash:",malware_data["md5_hash"])
        print("Signature:",malware_data["signature"])
        print("Tags:",malware_data["tags"])
        print("Intelligence:",malware_data["intelligence"])

if __name__ == "__main__":
    print("\nPE2H4x v1.0 Copyright <C> 2024-2025 w-knows")
    print("Lasted Version and Source Code: https://github.com/0x2ezy/PE2H4x\n")
    name, exe, imphash, image_base, RVA, EP, sections = get_info_pe()
    get_mal_info(imphash)
    input("\nPress Enter to exit...")
