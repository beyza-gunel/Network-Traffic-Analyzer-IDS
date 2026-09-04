# 🛡️ Network Traffic Analyzer & IDS

**PCAP Intelligence • Multi-Layer Detection • Risk Correlation • Flow Analytics**

Masaüstü tabanlı profesyonel bir **Network Traffic Analyzer & Intrusion Detection System (NTA/IDS)** uygulamasıdır.

> ⚠️ **Etik Kullanım:** Bu proje eğitim ve kontrollü laboratuvar kullanımı için geliştirilmiştir. Yalnızca sahibi olduğunuz veya analiz etme izniniz bulunan ağ kayıtları üzerinde kullanılmalıdır.

---

## ✨ Proje Özeti

Uygulama `.pcap` ve `.pcapng` ağ kayıtlarını analiz eder; paket ve flow seviyesinde trafik bilgilerini çıkarır, klasik ve kablosuz saldırıları tespit eder, risk skorunu hesaplar ve sonuçları profesyonel bir PySide6 dashboard üzerinde gösterir.

### ✅ Tamamlanan Ana Özellikler

- ✅ PCAP / PCAPNG analizi
- ✅ Packet Parser
- ✅ Traffic Analyzer
- ✅ Flow Analyzer
- ✅ Detection Engine
- ✅ Risk Correlation Engine
- ✅ Wireless IDS
- ✅ Timeline
- ✅ IP Analysis
- ✅ Network Graph
- ✅ JSON / HTML / PDF raporlama
- ✅ Background Worker + Progress Bar
- ✅ 16/16 Regression Test

---

## 🧭 Proje Mimarisi

```text
PCAP / NETWORK TRAFFIC
          ↓
     PACKET PARSER
          ↓
    TRAFFIC ANALYZER
          ↓
      FLOW ANALYZER
          ↓
    DETECTION ENGINE
          ↓
       RISK ENGINE
          ↓
 NORMAL / SUSPICIOUS
          ↓
         ALERT
          ↓
       DASHBOARD
          ↓
         REPORT
```

---

## 📦 PCAP Analizi

Uygulama:

- `.pcap` ve `.pcapng` dosyalarını analiz eder.
- Büyük dosyalarda `PcapReader` ile streaming okuma yapar.
- Analizi `QThread` üzerinden arka planda çalıştırır.
- Analiz sırasında progress bar gösterir.
- Bozuk ve geçersiz PCAP dosyalarını kontrol eder.
- Malformed paketlerde uygulamanın tamamen çökmesini engeller.

---

## 🔬 Paket Seviyesi Bilgiler

Uygulama mümkün olan paketlerde şu bilgileri çıkarır:

- Timestamp
- Source IP
- Destination IP
- Source Port
- Destination Port
- Protocol
- Packet Size
- TCP Flags
- DNS Query
- Source MAC
- Destination MAC
- BSSID
- 802.11 Frame Type
- HTTP / HTTPS / DNS bilgileri

### Desteklenen Trafik Türleri

`TCP` • `UDP` • `ICMP` • `ARP` • `DNS` • `HTTP` • `HTTPS` • `802.11 Wireless` • `EAPOL`

---

## 🖥️ Security Overview Dashboard

Dashboard üzerinde şu bilgiler gösterilir:

- 📦 Total Packets
- 🌐 Unique IPs
- 🔌 Unique Ports
- 🔁 TCP Connections
- 📡 UDP Traffic
- 🚨 Critical Alerts
- ⚠️ Suspicious Traffic
- 🛡️ Risk Level + Risk Score

### Risk Seviyeleri

| Seviye | Anlamı |
|---|---|
| 🟢 LOW | Düşük risk |
| 🟡 MEDIUM | İncelenmesi gereken trafik |
| 🟠 HIGH | Güçlü saldırı göstergesi |
| 🔴 CRITICAL | Çok yüksek / korele risk |

---

## 🛡️ Detection Engine

### Klasik Ağ Saldırıları

| Detection | Açıklama |
|---|---|
| PORT_SCAN | Çok sayıda farklı hedef porta erişim |
| SYN_SCAN | Pure SYN tabanlı port tarama |
| SYN_FLOOD | Yoğun SYN trafiği |
| ICMP_FLOOD | Yoğun ICMP trafiği |
| SMURF_ATTACK | Broadcast hedefli ICMP Echo |
| ARP_SPOOFING | Çakışan IP → MAC eşlemeleri |
| UNUSUAL_PORT_ACTIVITY | Şüpheli port kullanımı |
| DNS_ANOMALY | Anormal DNS sorgu davranışı |
| TRAFFIC_BURST | Kısa sürede olağan dışı trafik artışı |

### 📶 Wireless IDS

| Detection | Açıklama |
|---|---|
| DEAUTH_ATTACK | Deauthentication saldırısı |
| DISASSOCIATION_ATTACK | Disassociation saldırısı |
| ROGUE_AP | Şüpheli Access Point |
| EVIL_TWIN | Sahte / kopya Access Point |
| KRACK_ATTACK | WPA Message 3 / Replay Counter tekrarları |

---

## 🔐 KRACK Detection

KRACK detector şu koşulları birlikte değerlendirir:

```text
Aynı AP / istemci MAC çifti
        +
Aynı Replay Counter
        +
Capture boyunca en az 3 Message 3
        +
En az iki Message 3'ün 15 saniye içinde tekrarı
        ↓
KRACK_ATTACK
```

Gerçek `krack.pcap` üzerinde saldırı tespit edilmiştir.

`ewil.pcap` Evil Twin örneğinde ise yanlış KRACK alarmı oluşmadığı doğrulanmıştır.

---

## 🔁 Flow Analysis

Flows ekranında:

- Protocol
- Source
- Destination
- Source Port
- Destination Port
- Packet Count
- Byte Count
- Duration
- Forward Packets
- Reverse Packets
- Application Protocol
- NORMAL / SUSPICIOUS

bilgileri gösterilir.

---

## 📊 Analiz Ekranları

### 📦 Packets

Paket tablosu ve detay görünümü bulunur.

Filtreler:

- Source IP
- Destination IP
- Port
- Protocol
- Başlangıç tarihi / saati
- Bitiş tarihi / saati

### 🚨 Alerts

Alarm detaylarında:

- Alert Type
- Risk Level
- Source Entity
- Destination Entity
- Risk Score
- Confidence
- Packet Count
- Reason
- Evidence

gösterilir.

### ⏱️ Timeline

Trafik yoğunluğu ve güvenlik olayları zaman çizgisi üzerinde gösterilir.

### 🌐 IP Analysis

Her IP için:

- Packet Count
- Protocols
- Ports
- Connections
- Risk Score
- Alert Count
- NORMAL / SUSPICIOUS

bilgileri hesaplanır.

### 🕸️ Network Graph

- IP trafiğinde IP tabanlı graph
- Wireless trafikte MAC / BSSID tabanlı graph
- Şüpheli varlıkların görsel ayrımı

### 🔁 Flows

Çift yönlü network flow bilgileri gösterilir.

---

## 📄 Raporlama

Analiz sonuçları şu formatlarda dışa aktarılabilir:

- 📄 JSON
- 🌐 HTML
- 📕 PDF

---

## ✅ Final Regression Test

Test komutu:

```powershell
python run_regression_tests.py
```

Final sonuç:

```text
PASS: 16
FAIL: 0
SKIPPED: 0
```

### Sentetik Testler

| Senaryo | Sonuç |
|---|---|
| Normal Web Traffic | ✅ LOW / alarm yok |
| Port Scan | ✅ PORT_SCAN / HIGH |
| SYN Scan | ✅ SYN_SCAN / HIGH |
| ICMP Flood | ✅ ICMP_FLOOD / HIGH |
| DNS Anomaly | ✅ DNS_ANOMALY / MEDIUM |
| Traffic Burst | ✅ TRAFFIC_BURST / MEDIUM |
| Combined Attack | ✅ CRITICAL |
| Disassociation | ✅ HIGH |

### Gerçek PCAP Testleri

| Senaryo | Sonuç |
|---|---|
| SYN Flood | ✅ SYN_FLOOD |
| Smurf | ✅ SMURF_ATTACK |
| MITM | ✅ ARP_SPOOFING |
| Deauthentication | ✅ DEAUTH_ATTACK |
| Rogue AP | ✅ ROGUE_AP |
| Evil Twin | ✅ EVIL_TWIN |
| KRACK | ✅ KRACK_ATTACK |

> 📌 Gerçek PCAP dosyaları repository'e eklenmez. `data/real_pcaps/` klasörü `.gitignore` içerisindedir.

---

## 🔒 Güvenlik ve Dayanıklılık

Projede:

- ✅ PCAP doğrulama
- ✅ Malformed PCAP hata yönetimi
- ✅ Streaming packet read
- ✅ Malformed packet exception handling
- ✅ File/path validation
- ✅ Background worker thread
- ✅ Kontrollü logging

uygulanmıştır.

---

## 🚀 Kurulum

### 1. Repository'i klonlayın

```bash
git clone https://github.com/beyza-gunel/Network-Traffic-Analyzer-IDS.git
cd Network-Traffic-Analyzer-IDS
```

### 2. Virtual Environment oluşturun

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

PowerShell engeli varsa:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\venv\Scripts\Activate.ps1
```

### 3. Bağımlılıkları yükleyin

```bash
pip install -r requirements.txt
```

### 4. Uygulamayı çalıştırın

```bash
python main.py
```

---

## 🎮 Kullanım

1. **PCAP DOSYASI SEÇ**
2. `.pcap` veya `.pcapng` dosyasını seç
3. **ANALİZİ BAŞLAT**
4. Progress bar üzerinden durumu takip et
5. Dashboard ve analiz sekmelerini incele
6. İstersen JSON / HTML / PDF rapor oluştur

---

## 🗂️ Proje Yapısı

```text
NetworkTrafficAnalyzer/
│
├── main.py
├── requirements.txt
├── README.md
├── run_regression_tests.py
│
├── core/
├── detectors/
├── models/
├── services/
├── workers/
├── ui/
├── utils/
│
└── data/
    ├── test_pcaps/
    └── real_pcaps/   # gitignored
```

---

## 🧰 Kullanılan Teknolojiler

- Python
- PySide6
- Scapy
- Matplotlib
- NetworkX
- Pandas

---

## 🏁 Proje Durumu

### ✅ FINAL APPLICATION COMPLETED

- ✅ Professional Dashboard
- ✅ Multi-Layer IDS
- ✅ Wireless IDS
- ✅ Risk Correlation
- ✅ Flow Analysis
- ✅ JSON / HTML / PDF Reports
- ✅ 16/16 Regression Test

---

## ⚖️ Etik Kullanım

Bu yazılım savunma, eğitim ve laboratuvar amaçlıdır.

İzinsiz ağ dinleme, saldırı gerçekleştirme veya üçüncü taraf sistemlerde yetkisiz test amacıyla kullanılmamalıdır.
