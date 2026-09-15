# 🛡️ Network Traffic Analyzer & IDS

**PCAP Intelligence • Multi-Layer Detection • Risk Correlation • Flow Analytics**

Masaüstü tabanlı profesyonel bir **Network Traffic Analyzer & Intrusion Detection System (NTA/IDS)** uygulamasıdır.

> ⚠️ **Etik Kullanım:** Bu proje eğitim ve kontrollü laboratuvar kullanımı için geliştirilmiştir. Yalnızca sahibi olduğunuz veya analiz etme izniniz bulunan ağ kayıtları üzerinde kullanılmalıdır.

---

## ✨ Proje Özeti

Uygulama `.pcap` ve `.pcapng` ağ kayıtlarını analiz eder; paket ve flow seviyesinde trafik bilgilerini çıkarır, klasik ve kablosuz saldırıları tespit eder, güvenlik olaylarını korele ederek **0–100 aralığında genel risk skoru** hesaplar ve sonuçları PySide6 tabanlı profesyonel bir güvenlik panelinde gösterir.

Projenin amacı yalnızca paketleri listelemek değil; ağ trafiğini analiz ederek **normal ve şüpheli davranışları ayırmak, saldırı belirtilerini tespit etmek, teknik kanıtları göstermek ve analiz sonucunu raporlamaktır.**

### ✅ Tamamlanan Ana Özellikler

- ✅ PCAP / PCAPNG analizi
- ✅ Packet Parser
- ✅ Traffic Analyzer
- ✅ Flow Analyzer
- ✅ Detection Engine
- ✅ 0–100 Risk Correlation Engine
- ✅ Wireless IDS
- ✅ Timeline
- ✅ IP Analysis
- ✅ Network Graph
- ✅ JSON / HTML / PDF / Excel raporlama
- ✅ Background Worker + Progress Bar
- ✅ Büyük PCAP dosyalarında streaming analiz
- ✅ Windows `.exe` paketleme
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

Her modül ayrı bir sorumluluk taşır. Paket seviyesi bilgiler önce trafik ve flow analizinden geçirilir, ardından detection kuralları çalıştırılır ve oluşan güvenlik olayları Risk Engine tarafından korele edilir.

---

## 📦 PCAP Analizi

Uygulama:

- `.pcap` ve `.pcapng` dosyalarını analiz eder.
- Büyük dosyalarda `PcapReader` ile streaming okuma yapar.
- Analizi `QThread` üzerinden arka planda çalıştırır.
- Analiz sırasında progress bar gösterir.
- Bozuk ve geçersiz PCAP dosyalarını kontrol eder.
- Malformed paketlerin uygulamanın tamamen çökmesine neden olmasını engeller.
- Gerçek PCAP dosyalarında paket zamanlarını okunabilir tarih/saat biçiminde gösterir.
- Sentetik test PCAP'lerinde zamanı yakalama başlangıcına göre göreli saniye olarak gösterir.

---

## 🔬 Paket Seviyesi Bilgiler

Uygulama desteklenen paketlerde şu bilgileri çıkarır:

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

---

## 🧮 Risk Correlation Engine

Genel risk skoru **0–100** aralığında hesaplanır.

| Skor | Seviye | Anlamı |
|---|---|---|
| 0–24 | 🟢 LOW | Düşük risk |
| 25–49 | 🟡 MEDIUM | İncelenmesi gereken trafik |
| 50–74 | 🟠 HIGH | Güçlü saldırı göstergesi |
| 75–100 | 🔴 CRITICAL | Çok yüksek / korele risk |

Risk Engine yalnızca detector skorlarını doğrudan toplamaz.

Genel risk hesaplamasında:

- En yüksek alarm seviyesi
- Birden fazla alarmın birlikte görülmesi
- Birbirinden farklı saldırı türlerinin korelasyonu

değerlendirilir.

### Örnek: `combined_attack.pcap`

```text
En yüksek alarm seviyesi: HIGH
        ↓
Başlangıç risk skoru: 60

Birden fazla alarm:
        +5

3 farklı saldırı türü:
        +10

Sonuç:
75 / 100 → CRITICAL
```

Bu PCAP üzerinde:

- `PORT_SCAN`
- `SYN_SCAN`
- `ICMP_FLOOD`

tespitleri birlikte görülmektedir.

> ℹ️ Dashboard üzerindeki **Critical Alerts** değeri bireysel CRITICAL seviyeli alarm sayısını gösterirken, genel **Risk Level** farklı güvenlik olaylarının korelasyonu sonucunda CRITICAL olabilir.

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

Evil Twin örneğinde ise gerekli KRACK koşulları oluşmadığı için yanlış KRACK alarmı üretilmediği doğrulanmıştır.

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

Flow analizi sayesinde tek tek paketler yerine aynı ağ iletişimine ait paketlar toplu şekilde incelenebilir.

---

## 📊 Analiz Ekranları

### 📦 Packets

Paket tablosu ve paket detay görünümü bulunur.

Filtreler:

- Source IP
- Destination IP
- Port
- Protocol
- Başlangıç zamanı
- Bitiş zamanı

Gerçek PCAP dosyalarında okunabilir tarih/saat, sentetik test dosyalarında ise yakalama başlangıcına göre göreli zaman kullanılır.

---

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

---

### ⏱️ Timeline

Trafik yoğunluğu ve güvenlik olayları zaman çizgisi üzerinde gösterilir.

---

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

Şüpheli IP'ler için neden şüpheli olduklarını açıklayan güvenlik bilgileri de sunulur.

---

### 🕸️ Network Graph

- IP trafiğinde IP tabanlı graph
- Wireless trafikte MAC / BSSID tabanlı graph
- Ağ bağlantılarının görsel gösterimi
- Şüpheli varlıkların görsel ayrımı

---

### 🔁 Flows

Çift yönlü network flow bilgileri gösterilir.

---

## 📄 Raporlama

Analiz sonuçları şu formatlarda dışa aktarılabilir:

- 📄 JSON
- 🌐 HTML
- 📕 PDF
- 📊 Excel

Raporlarda analiz sonuçlarına göre:

- Genel güvenlik özeti
- Risk seviyesi ve risk skoru
- Paket / IP / port istatistikleri
- Protokol dağılımı
- Security alerts
- Teknik kanıtlar
- Flow bilgileri
- Önemli varlıklar
- Bağlantılar
- Öneriler
- Paket örnekleri

sunulur.

Excel raporları birden fazla çalışma sayfası kullanılarak yapılandırılmış şekilde oluşturulur.

---

## ✅ Regression Test

Test komutu:

```powershell
python run_regression_tests.py
```

Son doğrulama sonucu:

```text
PASS: 16
FAIL: 0
SKIPPED: 0
```

### Sentetik Testler

| Senaryo | Sonuç |
|---|---|
| Normal Web Traffic | ✅ LOW / Alarm yok |
| Port Scan | ✅ PORT_SCAN / HIGH |
| SYN Scan | ✅ SYN_SCAN / HIGH |
| ICMP Flood | ✅ ICMP_FLOOD / HIGH |
| DNS Anomaly | ✅ DNS_ANOMALY / MEDIUM |
| Traffic Burst | ✅ TRAFFIC_BURST / MEDIUM |
| Combined Attack | ✅ PORT_SCAN + SYN_SCAN + ICMP_FLOOD / CRITICAL / 75/100 |
| Disassociation | ✅ DISASSOCIATION_ATTACK / HIGH |

### Gerçek PCAP Testleri

| Senaryo | Sonuç |
|---|---|
| SYN Flood | ✅ SYN_FLOOD / CRITICAL |
| Smurf | ✅ SMURF_ATTACK / CRITICAL |
| MITM / ARP Spoofing | ✅ ARP_SPOOFING / CRITICAL |
| Deauthentication | ✅ DEAUTH_ATTACK / HIGH |
| Deauthentication - ikinci örnek | ✅ DEAUTH_ATTACK / HIGH |
| Rogue AP | ✅ ROGUE_AP / HIGH |
| Evil Twin | ✅ EVIL_TWIN / CRITICAL |
| KRACK | ✅ KRACK_ATTACK / CRITICAL |

Toplam:

```text
8 Sentetik Test
+
8 Gerçek PCAP Testi
=
16 / 16 PASS
```

> 📌 Gerçek saldırı PCAP dosyaları repository'e eklenmez. `data/real_pcaps/` klasörü `.gitignore` içerisindedir.

---

## 🔒 Güvenlik ve Dayanıklılık

Projede:

- ✅ PCAP doğrulama
- ✅ Malformed PCAP hata yönetimi
- ✅ Streaming packet read
- ✅ Malformed packet exception handling
- ✅ File / path validation
- ✅ Background worker thread
- ✅ Kontrollü logging
- ✅ Büyük PCAP dosyalarında arayüzü bloke etmeyen analiz yapısı

uygulanmıştır.

---

## 🚀 Kurulum

### 1. Repository'i Klonlayın

```bash
git clone https://github.com/beyza-gunel/Network-Traffic-Analyzer-IDS.git
cd Network-Traffic-Analyzer-IDS
```

### 2. Virtual Environment Oluşturun

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

PowerShell script çalıştırmayı engelliyorsa:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\venv\Scripts\Activate.ps1
```

Ardından:

```powershell
.\venv\Scripts\Activate.ps1
```

### 3. Bağımlılıkları Yükleyin

```bash
pip install -r requirements.txt
```

### 4. Uygulamayı Çalıştırın

```bash
python main.py
```

---

## 🖥️ Windows Masaüstü Uygulaması

Proje **PyInstaller** kullanılarak Windows üzerinde çalıştırılabilir `.exe` masaüstü uygulaması haline getirilebilir.

Paketleme komutu:

```powershell
pyinstaller --noconfirm --clean --windowed --name "NetworkTrafficAnalyzerIDS" main.py
```

Paketleme tamamlandıktan sonra:

```text
dist/
└── NetworkTrafficAnalyzerIDS/
    ├── NetworkTrafficAnalyzerIDS.exe
    └── _internal/
```

yapısı oluşur.

Uygulama:

```text
NetworkTrafficAnalyzerIDS.exe
```

dosyasına çift tıklanarak çalıştırılabilir.

### Önemli

`--onedir` paketleme yöntemi kullanıldığı için:

```text
NetworkTrafficAnalyzerIDS.exe
+
_internal/
```

birlikte tutulmalıdır.

`.exe` dosyasının tek başına başka bir klasöre taşınması önerilmez.

Paketlenmiş sürümün çalıştırılması için:

- VS Code açılması gerekmez.
- Virtual environment'ın manuel olarak etkinleştirilmesi gerekmez.
- `python main.py` komutunun çalıştırılması gerekmez.

> 📌 `build/`, `dist/` ve PyInstaller `.spec` dosyaları repository'e eklenmez.

Kaynak kod üzerinde değişiklik yapıldığında `.exe` sürümünün güncellenmesi için uygulama yeniden paketlenmelidir.

---

## 🎮 Kullanım

1. **PCAP DOSYASI SEÇ** butonuna basın.
2. `.pcap` veya `.pcapng` dosyasını seçin.
3. **ANALİZİ BAŞLAT** butonuna basın.
4. Progress bar üzerinden analiz durumunu takip edin.
5. Dashboard sonuçlarını inceleyin.
6. Packets, Alerts, Timeline, IP Analysis, Network Graph ve Flows sekmelerini inceleyin.
7. Gerekirse paketleri filtreleyin.
8. Analiz sonucunu JSON / HTML / PDF / Excel formatında dışa aktarın.

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
│   ├── packet_parser.py
│   ├── traffic_analyzer.py
│   ├── detection_engine.py
│   ├── risk_engine.py
│   └── flow_analyzer.py
│
├── detectors/
│   ├── port_scan.py
│   ├── syn_scan.py
│   ├── syn_flood.py
│   ├── icmp_flood.py
│   ├── smurf.py
│   ├── arp_spoofing.py
│   ├── unusual_port.py
│   ├── dns_anomaly.py
│   ├── traffic_burst.py
│   ├── deauth.py
│   ├── disassociation.py
│   ├── rogue_ap.py
│   ├── evil_twin.py
│   └── krack.py
│
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
- Pandas
- Matplotlib
- NetworkX
- OpenPyXL
- PyInstaller

---

## 🧪 Test Verileri

Repository içerisinde güvenli ve sentetik test PCAP dosyaları bulunur.

Örnek:

```text
data/test_pcaps/
├── normal_web_traffic.pcap
├── port_scan.pcap
├── syn_scan.pcap
├── icmp_flood.pcap
├── dns_anomaly.pcap
├── traffic_burst.pcap
├── combined_attack.pcap
└── disassociation.pcap
```

Gerçek saldırı PCAP dosyaları boyut, kaynak ve güvenlik nedenleriyle repository içerisinde tutulmaz.

---

## 🏁 Proje Durumu

### ✅ CORE APPLICATION COMPLETED

- ✅ Professional Security Dashboard
- ✅ PCAP / PCAPNG Analysis
- ✅ Packet Analysis
- ✅ Flow Analysis
- ✅ Multi-Layer IDS
- ✅ Wireless IDS
- ✅ 0–100 Risk Correlation Engine
- ✅ Timeline Analysis
- ✅ IP Analysis
- ✅ Network Graph
- ✅ JSON Reports
- ✅ HTML Reports
- ✅ PDF Reports
- ✅ Excel Reports
- ✅ Windows Executable Packaging
- ✅ Background Analysis
- ✅ Malformed PCAP Handling
- ✅ 16/16 Regression Test

---

## ⚖️ Etik Kullanım

Bu yazılım savunma, eğitim ve kontrollü laboratuvar amaçlıdır.

İzinsiz ağ dinleme, üçüncü taraf sistemlerde yetkisiz analiz, saldırı gerçekleştirme veya izinsiz güvenlik testi amacıyla kullanılmamalıdır.

Kullanıcı, analiz ettiği ağ trafiği ve PCAP kayıtları üzerinde gerekli izinlere sahip olmaktan sorumludur.

---

## 👩‍💻 Geliştirici

**Beyza Günel**

Bilgisayar Mühendisliği

GitHub: `beyza-gunel`

---

## 📌 Repository

```text
https://github.com/beyza-gunel/Network-Traffic-Analyzer-IDS
```