![Captura de pantalla 2024-03-04 165902](https://github.com/0x1v4n/PE2H4x/assets/131263019/61b2a81f-079a-445e-bf6d-dbfaefc90536)

                                               
# PE2H4x ~ Description
It is a tool that extracts data from the PE headers of an executable, calculates if it is obfuscated by means of entropy, and once it obtains the data, it uses the imphash to search for information and to be able to see to which malware family it could belong as well as to extract also the signature, hashes, size, among others.

# Features

### PE Info:
- Imphash
- Image Base
- EP,RVA
- Sections
- Size of Raw Data
- Entropy

### Analisys Info:
- Real Name
- Size
- First seen
- Hashes
- Signature
- Intelligence

# Usage

```pythonn
pip install requirements.txt
python3 <program.py>
```

### Interface
- *It has both a console and GUI version.*

# PoC (Proof on concept)

## CLI
![image](https://github.com/0x1v4n/PE2H4x/assets/131263019/c94b5a3b-f4b6-44c1-95c1-8d4233e8476d)

## GUI
![image](https://github.com/0x1v4n/PE2H4x/assets/131263019/87122c11-3679-48a1-b3cb-cdf7d73639f7)
![image](https://github.com/0x1v4n/PE2H4x/assets/131263019/e5f5eeff-bb72-4010-a24f-0de222cd88ff)

