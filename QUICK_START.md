# 🏴‍☠️ DARK-SHADOW CTF Platform - Quick Start

## 🚀 Fastest Way to Get Started

### Option 1: Use the Launcher (Recommended)
```powershell
python launch_ctf.py
```
Then select option 1 to setup, and option 2 or 3 to run!

### Option 2: Manual Setup
```powershell
# 1. Setup the platform
python setup_ctf.py

# 2a. Run command line version
python ctf_platform.py

# 2b. OR run web version
python ctf_web.py
# Then open: http://localhost:5000
```

## 🎯 What You Get

### 📁 Files Created
- **`ctf_platform.py`** - Command line CTF interface
- **`ctf_web.py`** - Web-based CTF interface 
- **`setup_ctf.py`** - Automated setup script
- **`launch_ctf.py`** - Simple launcher menu
- **`README.md`** - Complete documentation

### 🎮 Challenge Categories
1. **🌐 Web Security** - SQL Injection (100 pts)
2. **🔐 Cryptography** - Base64 (50 pts), Caesar Cipher (75 pts)
3. **🔍 Forensics** - Hidden Message (80 pts)
4. **🔄 Reverse Engineering** - Python Script (120 pts)
5. **🎯 Miscellaneous** - QR Code (60 pts)
6. **🕵️ OSINT** - Social Engineering (90 pts)
7. **💥 Binary Exploitation** - Buffer Overflow (150 pts)

**Total Points Available: 625**

## 🏆 Sample Flags (Spoilers!)

- Web SQL Injection: `CTF{sql_1nj3ct10n_m4st3r}`
- Crypto Base64: `CTF{b4s3_64_1s_n0t_3ncrypt10n}`
- Crypto Caesar: `CTF{c4354r_c1ph3r_15_345y}`
- Forensics Hidden: `CTF{h1dd3n_1n_pl41n_51ght}`
- Reverse Python: `CTF{r3v3rs3_3ng1n33r1ng_m4st3r}`
- Misc QR Code: `CTF{qr_c0d3_m4st3r}`
- OSINT Social: `CTF{051nt_1nv35t1g4t0r}`
- Binary Overflow: `CTF{buff3r_0v3rfl0w_b451c5}`

## 🎮 How to Play

### Command Line:
1. Enter player name
2. Choose "List Challenges" (option 1)
3. Choose "Solve Challenge" (option 2)
4. Submit flags in format: `CTF{...}`

### Web Interface:
1. Enter player name
2. Browse challenges by category
3. Click challenge → View details → Submit flag

## 🔧 Admin Features

- **Admin Password**: `admin123` (change this!)
- Create new challenges
- Generate challenge files
- Export progress

## 🎯 Tips for Solving

### Web - SQL Injection
- Look at HTML source comments
- Try: `admin' OR '1'='1' --`

### Crypto - Base64
- Use online base64 decoder
- Or Python: `base64.b64decode()`

### Crypto - Caesar/ROT13
- Use online ROT13 decoder
- Or shift each letter by 13

### Forensics - Hidden Message
- Check entire file content
- Look at the end of the file

### Reverse - Python Script
- Read the source code
- Find the secret password: `reverse_me`

## 🚀 Ready to Start?

```powershell
python launch_ctf.py
```

**Happy Hacking! 🏴‍☠️**
