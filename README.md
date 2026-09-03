# Network Traffic Analyzer & Intrusion Detection System

Bu proje, PCAP/PCAPNG dosyalarındaki ağ trafiğini analiz etmek, normal ve şüpheli ağ davranışlarını ayırt etmek ve belirlenen güvenlik kurallarına göre saldırı belirtilerini tespit etmek amacıyla geliştirilmiş masaüstü tabanlı bir Network Traffic Analyzer ve Network Intrusion Detection System (NIDS) uygulamasıdır.

Uygulama ağ paketlerini ayrıştırır, trafik istatistiklerini çıkarır, saldırı tespit kurallarını çalıştırır, bulunan güvenlik olaylarını risk puanlarıyla değerlendirir ve sonuçları grafik arayüz üzerinden kullanıcıya sunar.

---

## Proje Mimarisi

```text
PCAP / PCAPNG
      ↓
Packet Parser
      ↓
Traffic Analyzer
      ↓
Detection Engine
      ↓
Risk Engine
      ↓
Normal / Suspicious Traffic
      ↓
Alert
      ↓
Dashboard
```

Proje, modüler ve genişletilebilir bir mimari kullanılarak geliştirilmiştir.

---

## Kullanılan Teknolojiler

- Python
- Scapy
- PySide6
- Pandas
- Matplotlib
- NetworkX

---

## Temel Özellikler

- PCAP ve PCAPNG dosyası seçme
- Ağ paketlerini ayrıştırma
- Arka planda PCAP analizi
- PCAP dosyalarının `PcapReader` ile sıralı okunması
- Paket tablosu görüntüleme
- Paket detaylarını görüntüleme
- Kaynak IP filtresi
- Hedef IP filtresi
- Port filtresi
- Protokol filtresi
- Ağ trafik istatistikleri
- Otomatik saldırı tespiti
- Risk skoru hesaplama
- Alarm üretme
- LOW / MEDIUM / HIGH / CRITICAL risk seviyeleri
- İlişkili güvenlik olaylarının korelasyon ile değerlendirilmesi

---

## Desteklenen Protokoller ve Paket Bilgileri

Uygulama aşağıdaki ağ protokollerini ve paket özelliklerini analiz edebilmektedir:

- Ethernet
- ARP
- IPv4
- TCP
- UDP
- ICMP
- DNS
- IEEE 802.11 Wi-Fi
- EAPOL / WPA Handshake

Paketlerden çıkarılabilen başlıca bilgiler:

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
- ARP bilgileri
- ICMP Type / Code
- WLAN Type / Subtype
- SSID
- BSSID
- Wi-Fi Channel
- EAPOL Replay Counter
- EAPOL Key bilgileri

---

## Saldırı Tespit Modülleri

Uygulamada farklı ağ ve kablosuz ağ saldırıları için bağımsız detector modülleri bulunmaktadır.

### Network Attack Detection

- Port Scan Detection
- SYN Scan Detection
- SYN Flood Detection
- ICMP Flood Detection
- Smurf Attack Detection
- ARP Spoofing / MITM Detection
- DNS Anomaly Detection
- Unusual Port Activity Detection
- Suspicious Traffic Burst Detection

### Wireless Attack Detection

- Deauthentication Attack Detection
- Disassociation Attack Detection
- Rogue Access Point Detection
- Evil Twin Detection
- KRACK Attack Detection

---

## Risk Engine

Detection Engine tarafından oluşturulan alarmlar Risk Engine tarafından değerlendirilir.

| Risk Seviyesi | Açıklama |
|---|---|
| LOW | Normal veya düşük riskli trafik |
| MEDIUM | İncelenmesi gereken şüpheli davranış |
| HIGH | Güçlü saldırı göstergesi |
| CRITICAL | Birden fazla veya yüksek önem dereceli saldırı göstergesi |

Risk Engine, aynı olaydan kaynaklanan bazı alarmları korelasyon yöntemiyle değerlendirerek risk puanının gereksiz şekilde yükselmesini önlemeye çalışır.

Örnek:

```text
SYN Flood
+
Traffic Burst
↓
Correlated Risk
```

ve

```text
Evil Twin
+
Rogue AP
↓
Correlated Risk
```

---

## Gerçek PCAP Testleri

Uygulama gerçek saldırı trafiği içeren PCAP dosyaları üzerinde test edilmiştir.

Test edilen başlıca saldırılar:

- SYN Flood
- Smurf Attack
- ARP Spoofing / MITM
- Deauthentication
- Rogue AP
- Evil Twin
- KRACK

Gerçek saldırı PCAP dosyaları boyutları ve veri kaynağı nedeniyle GitHub deposuna dahil edilmemektedir.

---

## Sentetik Test PCAP Dosyaları

Detector modüllerinin kontrollü şekilde test edilebilmesi için sentetik PCAP dosyaları oluşturulmuştur.

Test senaryoları arasında:

- Normal Traffic
- Port Scan
- SYN Scan
- ICMP Flood
- DNS Anomaly
- Traffic Burst
- Combined Attack
- Disassociation Attack

bulunmaktadır.

Test PCAP dosyaları:

```text
data/test_pcaps/
```

dizini altında bulunmaktadır.

---

## Proje Yapısı

```text
NetworkTrafficAnalyzer/
│
├── main.py
├── README.md
├── requirements.txt
│
├── core/
│   ├── packet_parser.py
│   ├── traffic_analyzer.py
│   ├── detection_engine.py
│   └── risk_engine.py
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
│   ├── packet.py
│   ├── alert.py
│   ├── analysis_result.py
│   └── ip_info.py
│
├── services/
│   └── analysis_service.py
│
├── workers/
│   └── analysis_worker.py
│
├── ui/
│   └── main_window.py
│
├── utils/
│   └── runtime_env.py
│
└── data/
    ├── test_pcaps/
    └── real_pcaps/
```

---

## Kurulum

Projeyi bilgisayara klonlayın:

```bash
git clone https://github.com/beyza-gunel/Network-Traffic-Analyzer-IDS.git
```

Proje dizinine girin:

```bash
cd Network-Traffic-Analyzer-IDS
```

Sanal ortam oluşturun:

```bash
python -m venv venv
```

Windows PowerShell üzerinde sanal ortamı aktif edin:

```powershell
.\venv\Scripts\Activate.ps1
```

Gerekli paketleri yükleyin:

```bash
pip install -r requirements.txt
```

---

## Uygulamayı Çalıştırma

Projenin ana dizininde:

```bash
python main.py
```

komutu çalıştırılır.

Ardından:

1. `PCAP DOSYASI SEÇ` butonu ile `.pcap` veya `.pcapng` dosyası seçilir.
2. `ANALİZİ BAŞLAT` butonuna basılır.
3. Paketler arka planda analiz edilir.
4. Trafik istatistikleri hesaplanır.
5. Detection Engine güvenlik kurallarını çalıştırır.
6. Risk Engine genel risk seviyesini belirler.
7. Paketler ve güvenlik alarmları arayüzde görüntülenir.

---

## Performans

PCAP dosyalarının işlenmesinde Scapy `PcapReader` kullanılmaktadır.

Paketlerin sıralı olarak okunması, büyük PCAP dosyalarında Scapy paketlerinin tamamının aynı anda belleğe alınmasını önlemeye yardımcı olur.

Analiz işlemi PySide6 `QThread` tabanlı Worker mimarisi ile kullanıcı arayüzünden ayrılmıştır.

Bu sayede uzun süren PCAP analizlerinin GUI ana iş parçacığını doğrudan bloklaması önlenmektedir.

---

## Güvenlik ve Hata Yönetimi

Uygulamada:

- Hatalı paketlerin kontrollü şekilde atlanması
- PCAP okuma hatalarının yakalanması
- Aynı anda birden fazla analiz başlatılmasının engellenmesi
- PCAP paketlerinin sıralı okunması
- Analiz işlemlerinin ayrı Worker Thread üzerinde çalıştırılması

gibi kararlılık ve hata yönetimi önlemleri bulunmaktadır.

---

## Proje Durumu

Projenin temel PCAP analiz, trafik analiz, saldırı tespit ve risk değerlendirme altyapısı tamamlanmıştır.

Geliştirme sürecinin sonraki aşamalarında:

- Traffic Timeline
- IP Analysis
- Network Connection Graph
- Gelişmiş alarm filtreleme
- Tarih/saat filtreleri
- Alarm detay ve evidence ekranı
- JSON / HTML / PDF raporlama
- Profesyonel dashboard tasarımı
- Görsel trafik analizleri
- Final test ve performans iyileştirmeleri

üzerinde çalışılacaktır.