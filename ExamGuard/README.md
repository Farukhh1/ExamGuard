# ExamGuard

**AI Cheating Prevention & Centralized Exam Monitoring System**

ExamGuard is a network-level tool that blocks access to LLM/AI websites (ChatGPT, Claude, Gemini, Copilot, etc.) for all devices connected to an instructor's mobile hotspot during an exam, and gives the instructor a real-time dashboard to monitor connected devices and access attempts.

Built as a project for an Information Security course.

---

## How It Works

ExamGuard runs on the instructor's laptop and intercepts network traffic at multiple layers to reliably block AI websites for every device connected to the instructor's hotspot — even if a student tries switching Wi-Fi networks, using a different browser, or accessing a site via HTTPS.

| Component | Port | Purpose |
|---|---|---|
| DNS Proxy | 53 | Intercepts DNS queries from hotspot clients and blocks AI domains by resolving them to the instructor's IP instead of forwarding them |
| HTTPS Intercept | 443 | Reads the TLS ClientHello (SNI) to detect which blocked domain was requested, even over encrypted connections |
| HTTP Intercept | 80 | Serves a "blocked" warning page to students and logs the attempt |
| Flask Dashboard | 5000 | Real-time monitoring dashboard for the instructor (SOC-style UI) |
| Background Scanner | — | Periodically scans the ARP table to detect connected student devices |

When a student's device tries to reach a blocked AI site, ExamGuard:
1. Blocks the request at the DNS/HTTP/HTTPS layer
2. Identifies the device (IP, MAC address, hostname) via ARP + hostname resolution
3. Logs the attempt
4. Pushes a real-time alert to the instructor's dashboard via WebSockets (Socket.IO)

---

## Features

-  Blocks major AI/LLM sites: ChatGPT, OpenAI, Gemini, Claude, Copilot, Bard, Perplexity, You.com, Poe, Hugging Face
-  Auto-detects connected devices on the hotspot (with device name, IP, MAC)
-  Real-time alerts via WebSockets the moment a blocked site is accessed
-  Simple authenticated dashboard for the instructor
-  Toggle individual sites on/off from the dashboard
-  Persistent violation log
-  Automatically restores original DNS settings and cleans up firewall rules on exit

---

## Tech Stack

- **Backend:** Python, Flask, Flask-SocketIO
- **Frontend:** HTML, CSS, vanilla JS (Templates/Static)
- **Networking:** Raw sockets (custom DNS proxy), TLS ClientHello/SNI parsing, Windows ARP table scanning
- **Platform:** Windows (uses `netsh`, `ipconfig`, PowerShell `Get-DnsClientCache` / `Get-NetRoute`)

---

## Setup & Installation

> **Note:** ExamGuard is built for Windows, since it relies on Windows Mobile Hotspot, `netsh`, and PowerShell networking cmdlets.

### 1. Clone the repository
```bash
git clone https://github.com/Farukhh1/ExamGuard.git
cd ExamGuard/IS_PROJECT
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. (Optional) Configure credentials
By default, ExamGuard uses `admin` / `changeme` as the dashboard login. To set your own credentials, create a `.env` file in the `IS_PROJECT` folder (see `.env.example` for the format):
```
EXAMGUARD_USERNAME=admin
EXAMGUARD_PASSWORD=your_password_here
EXAMGUARD_SECRET_KEY=your_random_secret_key
```
If no `.env` file is present, the app falls back to the default credentials above.

### 4. Run as Administrator
ExamGuard needs admin privileges to modify the hosts file, configure DNS, and bind to low-numbered ports (53, 80, 443):
```bash
python app.py
```

### 5. Set up your hotspot
1. Connect your laptop to the internet (Ethernet or Wi-Fi)
2. Enable **Windows Mobile Hotspot**
3. Have students connect their phones/laptops to your hotspot
4. Open the dashboard at `http://<your-local-ip>:5000` and log in

Any attempt by a connected device to access a blocked AI site will trigger an instant alert on your dashboard.

---

## Default Login

```
Username: admin
Password: changeme
```

Override these via a local `.env` file (see above) — never commit real credentials to this repo.

---

## Project Structure
```
IS_PROJECT/
├── app.py              # Main application: DNS proxy, HTTP/HTTPS intercept, Flask dashboard
├── requirements.txt     # Python dependencies
├── Templates/
│   ├── login.html
│   └── dashboard.html
└── Static/
    └── style.css
```

---

## Documentation

- 📄 [Project Report](./ExamGuard.pdf)
- 🎥 [Tutorial / Demo Video](./Tutorial.mp4)

---

## Disclaimer

This project was built for educational purposes as part of a university course. It is intended for controlled exam environments with the explicit knowledge of participants, and should be used responsibly and in compliance with your institution's network and privacy policies.
