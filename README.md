# Network Device Mapper 🔍

A cyberpunk-themed network device mapper with pentesting features, real-time scanning, and automated security findings detection.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.11+-blue.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-0.109+-green.svg)

## ✨ Features

### 🌐 Network Discovery
- **ARP Scanning**: Fast local network device discovery
- **ICMP Ping Sweep**: Detect live hosts across subnets
- **Nmap Integration**: Advanced host discovery with MAC vendor lookup

### 🔓 Port Scanning
- **3 Scan Profiles**: Quick (100 ports), Standard (1000 ports), Deep (all ports)
- **Service Detection**: Identify services and versions running on open ports
- **OS Fingerprinting**: Guess operating system from network signatures

### 🔴 Security Findings
- **Auto-Detection**: Automatically identify 10+ common security issues
- **Risk Scoring**: Dynamic risk level calculation (Low/Medium/High/Critical)
- **Findings Database**: Track FTP, Telnet, SMB, RDP, database exposures, and more

### ⚡ Real-Time Updates
- **WebSocket Integration**: Live scan progress and device discovery
- **Instant Notifications**: Get alerts as findings are detected
- **Dynamic Dashboard**: Real-time stats and device updates

### 🎨 Cyberpunk UI
- **Dark Neon Theme**: Cyan, magenta, and lime accent colors
- **Glowing Effects**: Animated scan lines, neon pulses, and glitch effects
- **Monospace Fonts**: Terminal-style aesthetic

### 📊 Additional Features
- Device tagging and notes
- Scan history tracking
- Export to JSON/CSV/HTML
- Network topology visualization
- JWT-based authentication

## 🚀 Quick Start

### Prerequisites

- Python 3.11+
- Nmap (for scanning)
- pip

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/NetworkMapper.git
   cd NetworkMapper
   ```

2. **Set up backend**:
   ```bash
   cd backend
   python -m venv venv

   # Windows
   venv\Scripts\activate
   # Linux/Mac
   source venv/bin/activate

   pip install -r requirements.txt
   ```

3. **Configure environment**:
   ```bash
   # Copy .env.example to .env
   cp .env.example .env

   # Edit .env and set your SECRET_KEY
   ```

4. **Run backend**:
   ```bash
   # From backend directory
   python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
   ```

5. **Run frontend**:
   ```bash
   # In a new terminal, from project root
   cd frontend
   python -m http.server 3000
   ```

6. **Access the application**:
   - Frontend: http://localhost:3000
   - API Docs: http://localhost:8000/docs

## 📖 Usage

### First Time Setup

1. Open http://localhost:3000
2. Click "Register here" to create an account
3. Login with your credentials

### Running a Scan

1. Enter network CIDR (e.g., `192.168.1.0/24`)
2. Select scan profile:
   - **Quick**: Top 100 ports, fast
   - **Standard**: Top 1000 ports, service detection
   - **Deep**: All ports, OS detection (slow)
3. Click "Start Scan"
4. Watch real-time progress and device discovery

### Viewing Results

- **Dashboard**: See all discovered devices
- **Device Details**: Click "View" to see ports, findings, and scan history
- **Findings**: Review security issues and risk levels
- **Export**: Download results as JSON, CSV, or HTML report

## 🏗️ Architecture

### Backend (FastAPI)
```
backend/
├── app/
│   ├── main.py              # FastAPI application
│   ├── models/              # Database models
│   ├── schemas/             # Pydantic schemas
│   ├── api/routes/          # API endpoints
│   ├── services/            # Business logic
│   │   ├── scanner/         # Scanning modules
│   │   ├── analysis/        # Finding & risk analysis
│   │   └── websocket_manager.py
│   └── utils/               # Utilities
```

### Frontend (Vanilla JS)
```
frontend/
├── index.html               # Login page
├── dashboard.html           # Main dashboard
├── css/
│   ├── cyberpunk.css        # Neon theme
│   └── animations.css       # Effects
└── js/
    ├── auth.js              # Authentication
    ├── api-client.js        # API wrapper
    ├── websocket-client.js  # Real-time updates
    └── pages/
        └── dashboard.js     # Dashboard logic
```

## 🔧 Configuration

### Environment Variables (.env)

```env
# Database
DATABASE_URL=sqlite:///./data/networkmapper.db

# Security
SECRET_KEY=your-secret-key-here  # Change this!
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=15

# CORS
ALLOW_ORIGINS=http://localhost:3000

# Scanning
DEFAULT_SCAN_TIMEOUT=300
MAX_CONCURRENT_SCANS=3
```

## 🐳 Docker Deployment

```bash
# Build and run with Docker Compose
docker-compose up -d

# Access application
# Frontend: http://localhost:3000
# Backend: http://localhost:8000
```

## 📡 API Endpoints

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login and get JWT token
- `GET /api/auth/me` - Get current user info

### Scanning
- `POST /api/scans/discovery` - Start network discovery
- `POST /api/scans/device/{id}/ports` - Scan device ports
- `GET /api/scans/{id}` - Get scan details

### Devices
- `GET /api/devices` - List all devices
- `GET /api/devices/{id}` - Get device details
- `PUT /api/devices/{id}` - Update device info
- `GET /api/devices/{id}/ports` - Get device ports

### Findings
- `GET /api/findings` - List all findings
- `PUT /api/findings/{id}/acknowledge` - Acknowledge finding
- `POST /api/findings/analyze` - Analyze all devices
- `GET /api/findings/stats/summary` - Get statistics

### WebSocket
- `WS /ws?token=<jwt>` - Real-time updates

Full API documentation: http://localhost:8000/docs

## 🛡️ Security Findings Detected

The tool automatically detects these security issues:

| Finding | Severity | Ports |
|---------|----------|-------|
| FTP Service | Medium | 21 |
| Telnet Service | High | 23 |
| SSH Service | Info | 22 |
| HTTP Service | Low | 80, 8080, 8000 |
| SMB Service | Medium | 445, 139 |
| RDP Service | Medium | 3389 |
| MySQL Database | Medium | 3306 |
| PostgreSQL Database | Medium | 5432 |
| MongoDB Database | High | 27017 |
| Redis Cache | Medium | 6379 |

## ⚠️ Legal Disclaimer

**IMPORTANT**: This tool is designed for authorized security testing and network administration only.

- Only scan networks you own or have explicit permission to test
- Unauthorized network scanning may be illegal in your jurisdiction
- The authors are not responsible for misuse of this tool
- Always obtain written authorization before pentesting

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- **FastAPI** - Modern Python web framework
- **Nmap** - Network scanning engine
- **Scapy** - Packet manipulation library
- **Cytoscape.js** - Graph visualization
- **TailwindCSS** - Utility-first CSS framework

## 📧 Contact

Project Link: [https://github.com/yourusername/NetworkMapper](https://github.com/yourusername/NetworkMapper)

---

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>
