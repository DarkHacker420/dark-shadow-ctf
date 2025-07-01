# 🏴‍☠️ DARK-SHADOW CTF Platform

<div align="center">

![DARK-SHADOW CTF](https://img.shields.io/badge/DARK--SHADOW-CTF-brightgreen?style=for-the-badge&logo=hackaday&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.7+-blue?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-2.0+-red?style=for-the-badge&logo=flask&logoColor=white)
![Bootstrap](https://img.shields.io/badge/Bootstrap-5.3-purple?style=for-the-badge&logo=bootstrap&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-3.0+-green?style=for-the-badge&logo=sqlite&logoColor=white)

**🌟 Most Advanced & Beautiful CTF Platform for Cybersecurity Education 🌟**

*A cutting-edge Capture The Flag platform featuring modern UI, real-time analytics, and comprehensive cybersecurity challenges*

[🚀 Live Demo](https://your-app-name.onrender.com) • [📖 Features](#-features) • [⚡ Quick Start](#-quick-start) • [📚 Documentation](#-documentation) • [🤝 Contributing](#-contributing)

</div>

---

## 🎯 Overview

DARK-SHADOW CTF is an **advanced cybersecurity learning platform** that combines beautiful modern design with comprehensive security challenges. Built with Flask, Bootstrap 5, and enhanced with particle effects, real-time analytics, and dynamic progress tracking.

### 🌟 What Makes It Special?

- ✨ **Stunning Modern UI** - Bootstrap 5.3 with custom dark theme and particle.js effects
- 🏆 **Real-time Leaderboard** - Live rankings with country flags and detailed statistics  
- 📊 **Dynamic Progress Tracking** - Category-wise progress bars that update in real-time
- 🌍 **Multi-Country Support** - Including Pakistan 🇵🇰 and 12+ other countries
- 🎨 **Beautiful Challenge Cards** - Color-coded difficulty levels with solve indicators
- 📱 **Fully Responsive** - Perfect on desktop, tablet, and mobile devices
- 🔐 **Advanced Security Challenges** - 9 categories with 10+ professionally crafted challenges

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/dark-shadow-ctf.git
cd dark-shadow-ctf

# Install dependencies
pip install -r requirements.txt

# Launch the advanced web platform
python advanced_ctf_web.py
```

**🌐 Then open: http://localhost:5000**

🎉 **That's it! You're ready to hack!**

## 📋 Challenge Categories

| Category | Challenges | Difficulty | Points |
|----------|------------|------------|--------|
| 🌐 **Web Security** | SQL Injection Master, Reflected XSS Hunter | Easy-Medium | 100-120 |
| 🔐 **Cryptography** | Weak AES Implementation, RSA Small Exponent | Medium-Hard | 150-200 |
| 🔍 **Digital Forensics** | Hidden in Plain Sight (Steganography) | Medium | 130 |
| 🔄 **Reverse Engineering** | Advanced CrackMe | Hard | 180 |
| 💥 **Binary Exploitation** | Stack Overflow Mastery | Hard | 250 |
| 🕵️ **OSINT** | Social Media Investigation | Medium | 110 |
| 🎯 **Miscellaneous** | QR Code Puzzle Master | Easy | 90 |

### 🎯 Featured Challenges:

- **🌐 SQL Injection Master** (100 pts) - Exploit vulnerable login form to gain admin access
- **🌐 Reflected XSS Hunter** (120 pts) - Find and exploit reflected XSS vulnerability
- **🔐 Weak AES Implementation** (150 pts) - Break poorly implemented AES encryption
- **🔐 RSA Small Exponent Attack** (200 pts) - Exploit RSA with dangerously small public exponent
- **🔍 Hidden in Plain Sight** (130 pts) - Extract secret hidden using steganography
- **🔄 Advanced CrackMe** (180 pts) - Reverse engineer sophisticated binary
- **💥 Stack Overflow Mastery** (250 pts) - Exploit buffer overflow to gain shell access
- **🕵️ Social Media Investigation** (110 pts) - Track target's location using OSINT
- **🎯 QR Code Puzzle Master** (90 pts) - Solve multi-layered QR code puzzle

## 🎯 Flag Format

All flags follow the format: `CTF{flag_content_here}`

## 📁 File Structure

```
DARK-SHADOW-CTF/
├── advanced_ctf_web.py      # Advanced web platform (main file)
├── requirements.txt         # Python dependencies
├── README.md                # This file
├── templates/               # Beautiful HTML templates
│   ├── advanced_base.html
│   ├── advanced_login.html
│   ├── advanced_dashboard.html
│   ├── advanced_challenges.html
│   ├── advanced_leaderboard.html
│   ├── advanced_profile.html
│   └── advanced_challenge_detail.html
├── static/                  # Static files
│   └── challenges/          # Challenge downloads
├── challenges/              # Challenge files
│   ├── web/
│   └── osint/
└── ctf_data/               # SQLite database and user data
    └── ctf.db              # Main database
```

## 🛠️ Installation Requirements

- **Python 3.7+**
- **Flask 2.0+** (specified in requirements.txt)

```bash
pip install -r requirements.txt
```

## 🎮 How to Play

1. **Launch Platform**: Run `python advanced_ctf_web.py`
2. **Open Browser**: Navigate to http://localhost:5000
3. **Create Account**: Enter your hacker alias and select country
4. **Explore Dashboard**: View your progress and recent activity
5. **Choose Challenges**: Browse by category (Web Security, Crypto, etc.)
6. **Submit Flags**: Enter flags in format `CTF{...}` to earn points
7. **Track Progress**: Check leaderboard and profile stats
8. **Compete**: Climb the ranks and become the top hacker! 🏆

## 🏆 Scoring System

- **Easy**: 50-100 points
- **Medium**: 100-150 points  
- **Hard**: 150+ points

Points are awarded immediately upon correct flag submission.

## 📊 Platform Features

### ✅ Current Features
- 🎯 **9 Challenge Categories** - Web Security, Cryptography, Forensics, Reverse Engineering, Binary Exploitation, OSINT, and more
- 📊 **Real-time Progress Tracking** - Dynamic progress bars for each category
- 🏆 **Advanced Leaderboard** - Country flags, detailed statistics, and rankings
- 💾 **SQLite Database** - Persistent user data and challenge progress
- 🎨 **Modern UI/UX** - Bootstrap 5.3, Particle.js effects, responsive design
- 📱 **Mobile Responsive** - Perfect experience on all devices
- 🔐 **Secure Flag Submission** - Instant validation and scoring
- 📈 **Detailed Analytics** - User profiles with comprehensive statistics
- 🌍 **Multi-Country Support** - Including Pakistan 🇵🇰 and 12+ countries
- 🎭 **Beautiful Challenge Cards** - Color-coded difficulty and solve indicators

### 🚧 Upcoming Features
- 👥 **Team Competitions** - Collaborative solving
- ⏱️ **Time-based Scoring** - Dynamic point system
- 💡 **Advanced Hint System** - Progressive hints with penalties
- 🔗 **Challenge Dependencies** - Unlock advanced challenges
- 🔔 **Real-time Notifications** - Live updates and achievements
- 🐳 **Docker Deployment** - Easy containerized setup
- 📧 **Email Integration** - Password reset and notifications

## 🎯 Sample Challenges & Solutions

### Web - SQL Injection
**Challenge**: Find admin login bypass  
**Solution**: `admin' OR '1'='1' --`  
**Flag**: `CTF{sql_1nj3ct10n_m4st3r}`

### Crypto - Base64 Decode
**Challenge**: `Q1RGe2I0czNfNjRfMXNfbjB0XzNuY3J5cHQxMG59`  
**Solution**: Base64 decode  
**Flag**: `CTF{b4s3_64_1s_n0t_3ncrypt10n}`

### Crypto - Caesar Cipher  
**Challenge**: `PGS{p4354e_p1cu3e_15_345l}`  
**Solution**: ROT13 decrypt  
**Flag**: `CTF{c4354r_c1ph3r_15_345y}`

## 🔒 Security Notes

- This is a learning platform, not for production use
- Change default admin password
- Challenges are intentionally vulnerable for educational purposes
- Run in isolated environment

## 🤝 Contributing

1. Fork the repository
2. Create new challenges in appropriate categories  
3. Test thoroughly
4. Submit pull request

## 📞 Support

- Check challenge hints first
- Review this README
- Examine challenge files for clues
- Use online CTF resources for learning

## 🏆 Leaderboard

Track your progress and compete with others!
- Total score
- Challenges solved
- Category breakdown
- Time taken

## 🌐 Deployment Options

### 🚀 Free Hosting Platforms

#### Option 1: Render.com (Recommended)
1. Fork this repository
2. Connect your GitHub account to [Render.com](https://render.com)
3. Create a new Web Service
4. Connect your repository
5. Render will automatically use the `render.yaml` configuration

#### Option 2: Railway.app
1. Fork this repository
2. Visit [Railway.app](https://railway.app)
3. Connect GitHub and select your repository
4. Railway will auto-deploy using `railway.json`

#### Option 3: Vercel
1. Fork this repository
2. Visit [Vercel.com](https://vercel.com)
3. Import your GitHub repository
4. Vercel will use the `vercel.json` configuration

### 📋 Pre-deployment Checklist
- ✅ Fork the repository
- ✅ Ensure `requirements.txt` is present
- ✅ Check deployment config files (`render.yaml`, `railway.json`, `vercel.json`)
- ✅ Your app will be live at: `https://your-app-name.platform-domain.com`

---

**Happy Hacking! 🏴‍☠️**

*Remember: This platform is for educational purposes. Use your skills responsibly!*
