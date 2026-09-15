from __future__ import annotations

import html
import json
import math
import textwrap
from collections import Counter
from datetime import datetime
from pathlib import Path

from matplotlib.backends.backend_pdf import PdfPages
from matplotlib.figure import Figure
from matplotlib.patches import FancyBboxPatch, Rectangle


MAX_REPORT_PACKETS = 5000
TOP_ITEMS = 20
TIMELINE_BINS = 30
SYNTHETIC_EPOCH_THRESHOLD = 946684800  # 2000-01-01 00:00:00 UTC

# Professional, print-safe palette.
COLORS = {
    "navy": "#0B172A",
    "navy_2": "#12233D",
    "blue": "#168BCE",
    "cyan": "#2FB3E8",
    "green": "#2DBE7F",
    "yellow": "#E0A82E",
    "orange": "#E2782D",
    "red": "#D94B55",
    "purple": "#7568D8",
    "ink": "#182230",
    "muted": "#64748B",
    "line": "#D8E1EA",
    "soft": "#F3F6F9",
    "white": "#FFFFFF",
}

RISK_COLORS = {
    "LOW": COLORS["green"],
    "MEDIUM": COLORS["yellow"],
    "HIGH": COLORS["orange"],
    "CRITICAL": COLORS["red"],
}

RECOMMENDATIONS = {
    "PORT_SCAN": [
        "Kaynak varlığı ve hedeflenen portları doğrulayın; yetkisiz tarama ise olayı incelemeye alın.",
        "Gereksiz servisleri kapatın ve dışarıya açık portları en az yetki prensibine göre sınırlandırın.",
        "Gerekirse kaynak IP için firewall/rate-limit kuralı uygulayın ve tekrar eden taramaları izleyin.",
    ],
    "SYN_SCAN": [
        "SYN paketlerini gönderen kaynağı ve taranan hedef portları inceleyin.",
        "Firewall/IDS uzerinde bağlantı hizi sinirlama ve tarama tespit kurallarını etkinleştirin.",
        "Beklenmeyen açık portları ve servis bannerlarını kontrol edin.",
    ],
    "SYN_FLOOD": [
        "SYN rate-limit, SYN cookies ve edge firewall korumalarini etkinlestirin veya doğrulayın.",
        "Yoğunluk oluşturan kaynakları ve hedef servisin kaynak kullanımını izleyin.",
        "Kurumsal ortamda upstream/DDoS koruma servisiyle korelasyon yapın.",
    ],
    "ICMP_FLOOD": [
        "ICMP trafik hacmini ve kaynak dağılımıni inceleyin.",
        "Gerekli değilse ICMP hızını sınırlayın; tamamen kapatmak yerine ihtiyaca göre kontrollü filtreleme uygulayın.",
        "Aynı kaynaktan tekrar eden yüksek hacimli ICMP trafiğini SIEM/firewall kayıtlarıyla korele edin.",
    ],
    "SMURF_ATTACK": [
        "Directed broadcast özelliğini devre dışı bırakın ve broadcast ICMP davranışını kontrol edin.",
        "Spoofed source adreslerine karşı ingress/egress filtreleme uygulayın.",
        "Broadcast hedefli ICMP akislarini firewall ve router kayitlariyla doğrulayın.",
    ],
    "ARP_SPOOFING": [
        "Şüpheli IP-MAC eşleşmelerini switch ARP/MAC tablolarıyla doğrulayın.",
        "DHCP Snooping ve Dynamic ARP Inspection gibi L2 korumalarini etkinleştirmeyi değerlendirin.",
        "MITM ihtimali varsa etkilenen istemcilerin oturum ve kimlik bilgilerini gözden geçirin.",
    ],
    "UNUSUAL_PORT_ACTIVITY": [
        "Olağandışı port kullanımını ilgili servis ve istemci davranışıyla doğrulayın.",
        "Yetkisiz servisleri kapatın ve port erişimini segmentasyon/firewall politikalarıyla sinirlayin.",
    ],
    "DNS_ANOMALY": [
        "Şüpheli domainleri DNS loglari ve güvenilir tehdit istihbaratı kaynaklarıyla doğrulayın.",
        "Uzun, sık veya alışılmadık sorguları malware/DNS tunneling açısından inceleyin.",
        "Gerekirse zararlı domainleri DNS katmanında engelleyin ve etkilenen istemciyi izole edin.",
    ],
    "TRAFFIC_BURST": [
        "Ani trafik artışının planlı/normal bir iş yükünden kaynaklanıp kaynaklanmadığını doğrulayın.",
        "Kaynak-hedef çiftlerini, protokolleri ve paket hacmini baseline değerleriyle karşılaştırın.",
        "Anomali devam ediyorsa rate-limit ve segmentasyon politikalarını gözden geçirin.",
    ],
    "DEAUTH_ATTACK": [
        "Deauthentication framelerini gönderen MAC/BSSID ve kanali doğrulayın.",
        "Desteklenen ortamlarda 802.11w Protected Management Frames (PMF) ve WPA3 kullanın.",
        "Yetkisiz yayın kaynağını fiziksel olarak tespit edin ve kablosuz IDS kayıtlarıyla korele edin.",
    ],
    "DISASSOCIATION_ATTACK": [
        "Disassociation frame yoğunluğunu, kaynak MAC/BSSID ve hedef istemciyi inceleyin.",
        "PMF/802.11w desteğini etkinleştirin ve kablosuz altyapı firmware'ini güncel tutun.",
    ],
    "ROGUE_AP": [
        "SSID/BSSID bilgisini yetkili access point envanteriyle karşılaştırın.",
        "Yetkisiz AP doğrulanırsa ag erişimini kaldirin ve fiziksel kaynağı tespit edin.",
        "Kablosuz ağda periyodik rogue AP taramasi ve envanter doğrulaması uygulayın.",
    ],
    "EVIL_TWIN": [
        "Aynı SSID'yi yayınlayan farklı BSSID'leri yetkili AP listesiyle karşılaştırın.",
        "Kurumsal Wi-Fi için 802.1X/EAP ve sertifika doğrulamasını zorunlu tutun.",
        "Kullanıcıları sahte access point bağlantılarina karsi uyarin ve şüpheli AP'yi izole edin.",
    ],
    "KRACK_ATTACK": [
        "Access point ve istemci firmware/driver sürümlerinin KRACK yamalarını içerdiğini doğrulayın.",
        "Mümkünse WPA3 ve PMF kullanın; eski WPA2 istemcileri güncelleyin veya izole edin.",
        "Aynı Replay Counter ile tekrarlanan WPA Message 3 davranışını ek kablosuz kayıtlarla doğrulayın.",
    ],
    "IOC_MATCH": [
        "IOC eşleşmesini ikinci bir güvenilir tehdit istihbarati kaynağıyla doğrulayın.",
        "Etkilenen hostu izole edin ve ilgili IP/domain/hash icin kapsamli olay avcılığı yapın.",
    ],
}


def _safe_float(value, default=None):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _safe_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _fmt_number(value):
    try:
        return f"{int(value):,}".replace(",", ".")
    except (TypeError, ValueError):
        return str(value)


def _fmt_timestamp(value):
    timestamp = _safe_float(value)
    if timestamp is None:
        return "-"
    try:
        return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
    except (OSError, OverflowError, ValueError):
        return f"{timestamp:.3f}"


def _is_relative_capture(first_timestamp, last_timestamp):
    """Detect synthetic/test PCAPs that use Unix-epoch-near timestamps."""
    first = _safe_float(first_timestamp)
    last = _safe_float(last_timestamp)
    if first is None or last is None:
        return False
    return max(first, last) < SYNTHETIC_EPOCH_THRESHOLD


def _fmt_relative_timestamp(value, origin):
    timestamp = _safe_float(value)
    origin = _safe_float(origin)
    if timestamp is None or origin is None:
        return "-"
    delta = max(0.0, timestamp - origin)
    return f"{delta:.3f} sn"


def _fmt_report_timestamp(report, value):
    period = report.get("analysis_period", {}) if isinstance(report, dict) else {}
    if period.get("time_mode") == "relative":
        return _fmt_relative_timestamp(value, period.get("first_timestamp"))
    return _fmt_timestamp(value)


def _fmt_duration(seconds):
    seconds = _safe_float(seconds, 0.0) or 0.0
    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    if seconds < 60:
        return f"{seconds:.2f} sn"
    minutes, remainder = divmod(seconds, 60)
    if minutes < 60:
        return f"{int(minutes)} dk {remainder:.0f} sn"
    hours, minutes = divmod(minutes, 60)
    return f"{int(hours)} sa {int(minutes)} dk"


def _alert_level(alert):
    severity = str(alert.get("severity") or "").upper()

    if severity in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        return severity

    score = _safe_int(alert.get("risk_score"), 0)

    if score >= 12:
        return "CRITICAL"
    if score >= 10:
        return "HIGH"
    if score >= 5:
        return "MEDIUM"
    return "LOW"


def _json_safe(value):
    if value is None:
        return None
    if isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(item) for item in value]
    return str(value)


def _entity_from_alert(alert):
    return (
        alert.get("source_ip")
        or alert.get("source_mac")
        or alert.get("bssid")
        or "-"
    )


def _build_timeline(packets):
    points = []
    for packet in packets:
        timestamp = _safe_float(packet.get("timestamp"))
        if timestamp is None:
            continue
        points.append((timestamp, _safe_int(packet.get("packet_size"), 0)))

    if not points:
        return {
            "start": None,
            "end": None,
            "duration": 0.0,
            "bins": [],
        }

    points.sort(key=lambda item: item[0])
    start = points[0][0]
    end = points[-1][0]
    duration = max(0.0, end - start)

    if duration <= 0:
        return {
            "start": start,
            "end": end,
            "duration": duration,
            "bins": [
                {
                    "start": start,
                    "end": end,
                    "packets": len(points),
                    "bytes": sum(size for _, size in points),
                }
            ],
        }

    bin_count = min(TIMELINE_BINS, max(10, int(math.sqrt(len(points)))))
    bin_width = duration / bin_count
    bins = [
        {
            "start": start + index * bin_width,
            "end": start + (index + 1) * bin_width,
            "packets": 0,
            "bytes": 0,
        }
        for index in range(bin_count)
    ]

    for timestamp, packet_size in points:
        index = int((timestamp - start) / bin_width)
        index = min(max(index, 0), bin_count - 1)
        bins[index]["packets"] += 1
        bins[index]["bytes"] += packet_size

    return {
        "start": start,
        "end": end,
        "duration": duration,
        "bins": bins,
    }


def _build_executive_summary(report):
    alerts = report.get("alerts", [])
    risk = report.get("risk", {})
    stats = report.get("statistics", {})
    risk_level = str(risk.get("level", "LOW")).upper()
    risk_score = _safe_int(risk.get("score"), 0)
    total_packets = _safe_int(stats.get("total_packets"), 0)

    if not alerts:
        return (
            f"Analiz edilen {_fmt_number(total_packets)} paket icinde tanımlı saldırı kurallariyla "
            f"eşleşen bir güvenlik alarmi bulunmadı. Genel risk seviyesi {risk_level} "
            f"({risk_score}/100) olarak hesaplandı. Bu sonuç, PCAP icindeki görülebilir trafik icin "
            "alarm üretilmediğini ifade eder; tek başına tum agin risksiz olduğu anlamına gelmez."
        )

    alert_types = Counter(str(alert.get("type", "UNKNOWN")) for alert in alerts)
    ordered = ", ".join(
        f"{name} ({count})" if count > 1 else name
        for name, count in alert_types.most_common(5)
    )
    critical_count = sum(1 for alert in alerts if _alert_level(alert) == "CRITICAL")
    high_count = sum(1 for alert in alerts if _alert_level(alert) == "HIGH")

    entity_counter = Counter(
        _entity_from_alert(alert)
        for alert in alerts
        if _entity_from_alert(alert) != "-"
    )
    primary_entity = entity_counter.most_common(1)[0][0] if entity_counter else None

    text = (
        f"PCAP analizi {_fmt_number(total_packets)} paket uzerinde {len(alerts)} güvenlik alarmi üretti. "
        f"Genel risk seviyesi {risk_level} ({risk_score}/100). "
        f"Tespit edilen başlıca olaylar: {ordered}. "
    )

    if critical_count or high_count:
        text += f"Bunların {critical_count} tanesi CRITICAL, {high_count} tanesi HIGH seviyededir. "

    if primary_entity:
        text += f"Alarm kayıtlarında en çok öne çıkan kaynak/varlık: {primary_entity}. "

    text += (
        "Raporun sonraki sayfalarında trafik profili, zaman çizelgesi, alarmlarin teknik kanıtları "
        "ve önerilen aksiyonlar yer almaktadır."
    )
    return text


def _build_recommendations(alerts):
    items = []
    seen = set()

    for alert in sorted(
        alerts,
        key=lambda item: (_safe_int(item.get("risk_score"), 0), _safe_float(item.get("confidence"), 0) or 0),
        reverse=True,
    ):
        alert_type = str(alert.get("type", "UNKNOWN")).upper()
        for recommendation in RECOMMENDATIONS.get(alert_type, []):
            key = (alert_type, recommendation)
            if key in seen:
                continue
            seen.add(key)
            items.append(
                {
                    "alert_type": alert_type,
                    "level": _alert_level(alert),
                    "text": recommendation,
                }
            )

    if not items:
        items.append(
            {
                "alert_type": "GENERAL",
                "level": "LOW",
                "text": "Analiz sonucunu normal trafik baseline'ı ve diğer log kaynaklarıyla periyodik olarak karşılaştırın.",
            }
        )

    return items


def build_report_data(
    file_path,
    packets,
    statistics,
    alerts,
    risk_score,
    risk_level,
    risk_breakdown=None,
    flows=None,
):
    protocol_counter = Counter()
    app_protocol_counter = Counter()
    ip_counter = Counter()
    mac_counter = Counter()
    bssid_counter = Counter()
    ssid_counter = Counter()
    port_counter = Counter()
    connection_counter = Counter()

    first_timestamp = None
    last_timestamp = None
    total_bytes = 0

    for packet in packets:
        protocol = packet.get("protocol")
        if protocol:
            protocol_counter[str(protocol)] += 1

        app_protocol = packet.get("application_protocol")
        if app_protocol:
            app_protocol_counter[str(app_protocol)] += 1

        src_ip = packet.get("src_ip")
        dst_ip = packet.get("dst_ip")
        if src_ip:
            ip_counter[str(src_ip)] += 1
        if dst_ip:
            ip_counter[str(dst_ip)] += 1
        if src_ip and dst_ip and src_ip != dst_ip:
            connection_counter[(str(src_ip), str(dst_ip))] += 1

        src_mac = packet.get("src_mac")
        dst_mac = packet.get("dst_mac")
        if src_mac:
            mac_counter[str(src_mac)] += 1
        if dst_mac and str(dst_mac).lower() != "ff:ff:ff:ff:ff:ff":
            mac_counter[str(dst_mac)] += 1

        bssid = packet.get("bssid")
        if bssid:
            bssid_counter[str(bssid)] += 1

        ssid = packet.get("ssid")
        if ssid:
            ssid_counter[str(ssid)] += 1

        for port_key in ("src_port", "dst_port"):
            port = packet.get(port_key)
            if port is not None:
                port_counter[str(port)] += 1

        total_bytes += _safe_int(packet.get("packet_size"), 0)

        timestamp = _safe_float(packet.get("timestamp"))
        if timestamp is not None:
            if first_timestamp is None or timestamp < first_timestamp:
                first_timestamp = timestamp
            if last_timestamp is None or timestamp > last_timestamp:
                last_timestamp = timestamp

    prepared_alerts = []
    for alert in alerts:
        item = {
            **_json_safe(alert),
            "derived_level": _alert_level(alert),
        }
        prepared_alerts.append(item)

    alert_type_counter = Counter(alert.get("type", "UNKNOWN") for alert in prepared_alerts)
    alert_level_counter = Counter(alert.get("derived_level", "LOW") for alert in prepared_alerts)
    timeline = _build_timeline(packets)

    packet_sample = [_json_safe(packet) for packet in packets[:MAX_REPORT_PACKETS]]

    # Flow Analyzer çıktısını rapora dahil et. MainWindow, FlowRecord
    # nesnelerini doğrudan gönderir; JSON/PDF/HTML için güvenli sözlüklere
    # dönüştürürüz. Eski çağrılar için flows opsiyoneldir.
    prepared_flows = []
    for flow in (flows or []):
        if hasattr(flow, "to_dict"):
            flow_data = flow.to_dict()
        elif isinstance(flow, dict):
            flow_data = flow
        else:
            try:
                flow_data = vars(flow)
            except TypeError:
                flow_data = {"value": str(flow)}
        prepared_flows.append(_json_safe(flow_data))

    flow_app_counter = Counter(
        str(flow.get("application_protocol") or flow.get("protocol") or "UNKNOWN")
        for flow in prepared_flows
    )

    relative_capture = _is_relative_capture(first_timestamp, last_timestamp)
    duration_seconds = (
        max(0.0, (last_timestamp or 0) - (first_timestamp or 0))
        if first_timestamp is not None and last_timestamp is not None
        else 0.0
    )

    report = {
        "report_version": "2.1",
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "pcap_file": str(file_path or ""),
        "pcap_file_name": Path(file_path).name if file_path else "",
        "analysis_period": {
            "first_timestamp": first_timestamp,
            "last_timestamp": last_timestamp,
            "time_mode": "relative" if relative_capture else "absolute",
            "is_synthetic_time": relative_capture,
            "first_readable": (
                _fmt_relative_timestamp(first_timestamp, first_timestamp)
                if relative_capture
                else _fmt_timestamp(first_timestamp)
            ),
            "last_readable": (
                _fmt_relative_timestamp(last_timestamp, first_timestamp)
                if relative_capture
                else _fmt_timestamp(last_timestamp)
            ),
            "duration_seconds": duration_seconds,
            "note": (
                "Sentetik/test PCAP'i göreli zaman damgaları kullanıyor; "
                "1970 tarihi yerine yakalama başlangıcına göre süre gösterildi."
                if relative_capture
                else ""
            ),
        },
        "statistics": _json_safe(statistics),
        "traffic": {
            "total_bytes": total_bytes,
            "average_packet_size": round(total_bytes / len(packets), 2) if packets else 0.0,
        },
        "risk": {
            "score": _safe_int(risk_score, 0),
            "level": str(risk_level or "LOW").upper(),
            "breakdown": _json_safe(risk_breakdown or []),
        },
        "alerts": prepared_alerts,
        "summary": {
            "protocol_distribution": dict(protocol_counter),
            "application_protocol_distribution": dict(app_protocol_counter),
            "alert_type_distribution": dict(alert_type_counter),
            "alert_level_distribution": dict(alert_level_counter),
            "top_ips": [
                {"ip": ip, "packet_references": count}
                for ip, count in ip_counter.most_common(TOP_ITEMS)
            ],
            "top_macs": [
                {"mac": mac, "packet_references": count}
                for mac, count in mac_counter.most_common(TOP_ITEMS)
            ],
            "top_bssids": [
                {"bssid": bssid, "packet_references": count}
                for bssid, count in bssid_counter.most_common(TOP_ITEMS)
            ],
            "top_ssids": [
                {"ssid": ssid, "packet_references": count}
                for ssid, count in ssid_counter.most_common(TOP_ITEMS)
            ],
            "top_ports": [
                {"port": port, "packet_references": count}
                for port, count in port_counter.most_common(TOP_ITEMS)
            ],
            "top_connections": [
                {
                    "source_ip": source,
                    "destination_ip": destination,
                    "packets": count,
                }
                for (source, destination), count in connection_counter.most_common(TOP_ITEMS)
            ],
        },
        "timeline": timeline,
        "flows": prepared_flows,
        "flow_summary": {
            "count": len(prepared_flows),
            "application_distribution": dict(flow_app_counter),
            "top_flows": sorted(
                prepared_flows,
                key=lambda item: (
                    _safe_int(item.get("packet_count"), 0),
                    _safe_int(item.get("byte_count"), 0),
                ),
                reverse=True,
            )[:TOP_ITEMS],
        },
        "packet_sample": packet_sample,
        "packet_sample_limit": MAX_REPORT_PACKETS,
        "packet_sample_truncated": len(packets) > MAX_REPORT_PACKETS,
    }

    report["executive_summary"] = _build_executive_summary(report)
    report["recommendations"] = _build_recommendations(prepared_alerts)
    return report


def export_json(output_path, report_data):
    path = Path(output_path)
    path.write_text(
        json.dumps(report_data, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return path


def _html_escape(value):
    return html.escape(str(value if value is not None else ""))


def export_html(output_path, report_data):
    path = Path(output_path)
    stats = report_data.get("statistics", {})
    alerts = report_data.get("alerts", [])
    risk = report_data.get("risk", {})
    summary = report_data.get("summary", {})
    recommendations = report_data.get("recommendations", [])
    risk_level = str(risk.get("level", "LOW")).upper()
    risk_color = RISK_COLORS.get(risk_level, COLORS["muted"])

    protocol_rows = "".join(
        f"<tr><td>{_html_escape(protocol)}</td><td>{count}</td></tr>"
        for protocol, count in sorted(summary.get("protocol_distribution", {}).items())
    ) or "<tr><td colspan='2'>Protokol verisi bulunamadi.</td></tr>"

    alert_rows = []
    for alert in alerts:
        confidence = alert.get("confidence")
        if confidence is not None and _safe_float(confidence) is not None:
            confidence = f"{_safe_float(confidence) * 100:.0f}%" if _safe_float(confidence) <= 1 else f"{_safe_float(confidence):.0f}%"
        alert_rows.append(
            "<tr>"
            f"<td>{_html_escape(alert.get('type', 'UNKNOWN'))}</td>"
            f"<td>{_html_escape(alert.get('derived_level', ''))}</td>"
            f"<td>{_html_escape(alert.get('risk_score', 0))}</td>"
            f"<td>{_html_escape(confidence or '-')}</td>"
            f"<td>{_html_escape(alert.get('source_ip') or '-')}</td>"
            f"<td>{_html_escape(alert.get('destination_ip') or '-')}</td>"
            f"<td>{_html_escape(alert.get('packet_count') or 0)}</td>"
            f"<td>{_html_escape(alert.get('reason') or '-')}</td>"
            "</tr>"
        )

    if not alert_rows:
        alert_rows.append("<tr><td colspan='8'>Güvenlik alarmi tespit edilmedi.</td></tr>")

    recommendation_html = "".join(
        f"<li><b>{_html_escape(item.get('alert_type'))}:</b> {_html_escape(item.get('text'))}</li>"
        for item in recommendations
    )

    document = f"""<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Network Traffic Analyzer & IDS - Güvenlik Analiz Raporu</title>
<style>
    * {{ box-sizing: border-box; }}
    body {{ margin:0; background:#eef2f6; color:#182230; font-family:Arial,Helvetica,sans-serif; }}
    .page {{ max-width:1180px; margin:30px auto; background:white; border-radius:16px; overflow:hidden; box-shadow:0 8px 30px rgba(15,23,42,.08); }}
    .hero {{ background:#0B172A; color:white; padding:34px 40px; display:flex; justify-content:space-between; gap:24px; align-items:center; }}
    .hero h1 {{ margin:0 0 8px; font-size:30px; }}
    .hero p {{ margin:4px 0; color:#cbd5e1; }}
    .risk {{ min-width:210px; padding:20px; border-radius:14px; background:{risk_color}; text-align:center; }}
    .risk .level {{ font-size:26px; font-weight:800; }}
    .risk .score {{ font-size:18px; margin-top:4px; }}
    .section {{ padding:26px 40px; border-bottom:1px solid #e2e8f0; }}
    .section h2 {{ margin:0 0 16px; font-size:22px; }}
    .summary {{ background:#f8fafc; border-left:5px solid #168BCE; padding:16px 18px; line-height:1.55; border-radius:8px; }}
    .cards {{ display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:12px; }}
    .card {{ border:1px solid #dde5ee; border-radius:12px; padding:16px; }}
    .card .label {{ color:#64748B; font-size:13px; }}
    .card .value {{ font-size:24px; font-weight:800; margin-top:4px; }}
    table {{ width:100%; border-collapse:collapse; font-size:13px; }}
    th {{ background:#0B172A; color:white; text-align:left; padding:10px; }}
    td {{ padding:9px 10px; border-bottom:1px solid #e5e7eb; vertical-align:top; }}
    ul {{ padding-left:22px; line-height:1.55; }}
    .meta {{ display:grid; grid-template-columns:1fr 1fr; gap:10px 24px; }}
    .small {{ color:#64748B; font-size:12px; }}
    @media (max-width:800px) {{ .cards{{grid-template-columns:repeat(2,1fr)}} .hero{{display:block}} .risk{{margin-top:18px}} }}
</style>
</head>
<body>
<div class="page">
  <div class="hero">
    <div>
      <h1>Network Traffic Analyzer & IDS</h1>
      <p><b>Güvenlik Analiz Raporu</b></p>
      <p>PCAP: {_html_escape(report_data.get('pcap_file_name', ''))}</p>
      <p>Rapor tarihi: {_html_escape(report_data.get('generated_at', ''))}</p>
    </div>
    <div class="risk"><div>GENEL RİSK</div><div class="level">{_html_escape(risk_level)}</div><div class="score">{_html_escape(risk.get('score',0))}/100</div></div>
  </div>

  <div class="section">
    <h2>Yönetici Özeti</h2>
    <div class="summary">{_html_escape(report_data.get('executive_summary',''))}</div>
  </div>

  <div class="section">
    <h2>Trafik ve Risk Özeti</h2>
    <div class="cards">
      <div class="card"><div class="label">Toplam Paket</div><div class="value">{_fmt_number(stats.get('total_packets',0))}</div></div>
      <div class="card"><div class="label">Benzersiz IP</div><div class="value">{_fmt_number(stats.get('unique_ips',0))}</div></div>
      <div class="card"><div class="label">Benzersiz Port</div><div class="value">{_fmt_number(stats.get('unique_ports',0))}</div></div>
      <div class="card"><div class="label">TCP Bağlantısı</div><div class="value">{_fmt_number(stats.get('tcp_connections',0))}</div></div>
      <div class="card"><div class="label">UDP Trafik</div><div class="value">{_fmt_number(stats.get('udp_packets',0))}</div></div>
      <div class="card"><div class="label">Alarm</div><div class="value">{len(alerts)}</div></div>
      <div class="card"><div class="label">Risk Skoru</div><div class="value">{_html_escape(risk.get('score',0))}/100</div></div>
      <div class="card"><div class="label">Süre</div><div class="value" style="font-size:18px">{_fmt_duration(report_data.get('analysis_period',{}).get('duration_seconds',0))}</div></div>
    </div>
  </div>

  <div class="section">
    <h2>Protokol Dağılımı</h2>
    <table><thead><tr><th>Protokol</th><th>Paket</th></tr></thead><tbody>{protocol_rows}</tbody></table>
  </div>

  <div class="section">
    <h2>Güvenlik Alarmları</h2>
    <table><thead><tr><th>Tip</th><th>Seviye</th><th>Risk</th><th>Güven</th><th>Kaynak</th><th>Hedef</th><th>Paket</th><th>Neden</th></tr></thead><tbody>{''.join(alert_rows)}</tbody></table>
  </div>

  <div class="section">
    <h2>Önerilen Aksiyonlar</h2>
    <ul>{recommendation_html}</ul>
  </div>

  <div class="section small">
    Bu rapor, PCAP/PCAPNG dosyasindan cikartilan görülebilir ag verileri ve uygulamanin kural tabanlı IDS motoru uzerinden otomatik olarak uretilmistir. Bulgular, olay incelemesinde diger log kaynaklari ve ağ envanteriyle birlikte değerlendirilmelidir.
  </div>
</div>
</body>
</html>"""

    path.write_text(document, encoding="utf-8")
    return path


def _new_figure():
    figure = Figure(figsize=(8.27, 11.69), facecolor=COLORS["white"])
    return figure


def _save_page(pdf, figure):
    pdf.savefig(figure, bbox_inches="tight", facecolor=figure.get_facecolor())


def _page_header(figure, title, subtitle=None, page_label=None):
    figure.text(0.07, 0.955, title, fontsize=17, fontweight="bold", color=COLORS["navy"], va="top")
    if subtitle:
        figure.text(0.07, 0.927, subtitle, fontsize=9, color=COLORS["muted"], va="top")
    if page_label:
        figure.text(0.93, 0.952, page_label, fontsize=8, color=COLORS["muted"], ha="right", va="top")
    figure.add_artist(Rectangle((0.07, 0.91), 0.86, 0.0025, transform=figure.transFigure, color=COLORS["line"], linewidth=0))


def _footer(figure, text="Network Traffic Analyzer & IDS - Otomatik Güvenlik Analizi"):
    figure.add_artist(Rectangle((0.07, 0.045), 0.86, 0.0015, transform=figure.transFigure, color=COLORS["line"], linewidth=0))
    figure.text(0.07, 0.025, text, fontsize=7.5, color=COLORS["muted"], va="bottom")


def _draw_card(figure, x, y, w, h, label, value, accent=None, value_size=17, subtitle=None):
    accent = accent or COLORS["blue"]
    patch = FancyBboxPatch(
        (x, y), w, h,
        transform=figure.transFigure,
        boxstyle="round,pad=0.008,rounding_size=0.012",
        linewidth=0.8,
        edgecolor=COLORS["line"],
        facecolor=COLORS["white"],
    )
    figure.add_artist(patch)
    figure.add_artist(Rectangle((x, y), 0.006, h, transform=figure.transFigure, color=accent, linewidth=0))
    figure.text(x + 0.02, y + h - 0.025, label, fontsize=8.5, color=COLORS["muted"], va="top")
    figure.text(x + 0.02, y + 0.038, str(value), fontsize=value_size, fontweight="bold", color=COLORS["ink"], va="bottom")
    if subtitle:
        figure.text(x + 0.02, y + 0.014, subtitle, fontsize=7.2, color=COLORS["muted"], va="bottom")


def _draw_wrapped_text(figure, x, y, text, width=105, fontsize=9.5, color=None, line_height=0.024, max_lines=None, weight="normal"):
    lines = textwrap.wrap(str(text), width=width) or [""]
    if max_lines is not None:
        lines = lines[:max_lines]
    current_y = y
    for line in lines:
        figure.text(x, current_y, line, fontsize=fontsize, color=color or COLORS["ink"], va="top", fontweight=weight)
        current_y -= line_height
    return current_y


def _confidence_text(value):
    number = _safe_float(value)
    if number is None:
        return "-"
    if number <= 1:
        number *= 100
    return f"{number:.0f}%"


def _entity(alert, source=True):
    if source:
        return alert.get("source_ip") or alert.get("source_mac") or alert.get("bssid") or "-"
    return alert.get("destination_ip") or alert.get("destination_mac") or "-"


def _draw_cover_page(pdf, report):
    figure = _new_figure()
    risk = report.get("risk", {})
    stats = report.get("statistics", {})
    alerts = report.get("alerts", [])
    risk_level = str(risk.get("level", "LOW")).upper()
    risk_color = RISK_COLORS.get(risk_level, COLORS["muted"])

    figure.add_artist(Rectangle((0, 0.80), 1, 0.20, transform=figure.transFigure, color=COLORS["navy"], linewidth=0))
    figure.text(0.07, 0.94, "NETWORK TRAFFIC ANALYZER & IDS", fontsize=19, fontweight="bold", color=COLORS["white"], va="top")
    figure.text(0.07, 0.895, "Güvenlik Analiz Raporu", fontsize=13, color="#D5E2F2", va="top")
    figure.text(0.07, 0.84, f"PCAP: {report.get('pcap_file_name','-')}", fontsize=10, color=COLORS["white"], va="top")
    figure.text(0.07, 0.815, f"Rapor tarihi: {report.get('generated_at','-')}", fontsize=8.5, color="#B9C8DA", va="top")

    badge = FancyBboxPatch((0.69, 0.835), 0.23, 0.105, transform=figure.transFigure, boxstyle="round,pad=0.012,rounding_size=0.015", linewidth=0, facecolor=risk_color)
    figure.add_artist(badge)
    figure.text(0.805, 0.915, "GENEL RİSK", fontsize=8.5, color=COLORS["white"], ha="center", va="top")
    figure.text(0.805, 0.885, risk_level, fontsize=18, fontweight="bold", color=COLORS["white"], ha="center", va="center")
    figure.text(0.805, 0.848, f"{risk.get('score',0)}/100", fontsize=11, color=COLORS["white"], ha="center", va="center")

    figure.text(0.07, 0.755, "Yönetici Özeti", fontsize=14, fontweight="bold", color=COLORS["navy"], va="top")
    box = FancyBboxPatch((0.07, 0.61), 0.86, 0.12, transform=figure.transFigure, boxstyle="round,pad=0.012,rounding_size=0.012", linewidth=0.8, edgecolor=COLORS["line"], facecolor=COLORS["soft"])
    figure.add_artist(box)
    _draw_wrapped_text(figure, 0.09, 0.705, report.get("executive_summary", ""), width=112, fontsize=9.2, line_height=0.021, max_lines=5)

    card_w, card_h = 0.195, 0.105
    xs = [0.07, 0.285, 0.50, 0.715]
    y1, y2 = 0.455, 0.325
    _draw_card(figure, xs[0], y1, card_w, card_h, "Toplam Paket", _fmt_number(stats.get("total_packets", 0)), COLORS["blue"], subtitle="Captured frames")
    _draw_card(figure, xs[1], y1, card_w, card_h, "Benzersiz IP", _fmt_number(stats.get("unique_ips", 0)), COLORS["purple"], subtitle="Observed endpoints")
    _draw_card(figure, xs[2], y1, card_w, card_h, "Benzersiz Port", _fmt_number(stats.get("unique_ports", 0)), COLORS["cyan"], subtitle="Observed ports")
    _draw_card(figure, xs[3], y1, card_w, card_h, "TCP Bağlantısı", _fmt_number(stats.get("tcp_connections", 0)), COLORS["green"], subtitle="Bidirectional sessions")
    _draw_card(figure, xs[0], y2, card_w, card_h, "UDP Trafik", _fmt_number(stats.get("udp_packets", 0)), COLORS["purple"], subtitle="UDP packets")
    _draw_card(figure, xs[1], y2, card_w, card_h, "Güvenlik Alarmi", len(alerts), COLORS["orange"], subtitle="Generated alerts")
    _draw_card(figure, xs[2], y2, card_w, card_h, "Trafik Süresi", _fmt_duration(report.get("analysis_period", {}).get("duration_seconds", 0)), COLORS["blue"], value_size=13.5, subtitle="PCAP time span")
    _draw_card(figure, xs[3], y2, card_w, card_h, "Veri Hacmi", _fmt_number(report.get("traffic", {}).get("total_bytes", 0)) + " B", COLORS["cyan"], value_size=13.5, subtitle="Captured bytes")

    figure.text(0.07, 0.255, "Analiz Aralığı", fontsize=10.5, fontweight="bold", color=COLORS["navy"], va="top")
    period = report.get("analysis_period", {})
    figure.text(0.07, 0.225, f"İlk paket: {period.get('first_readable','-')}", fontsize=8.8, color=COLORS["ink"], va="top")
    figure.text(0.50, 0.225, f"Son paket: {period.get('last_readable','-')}", fontsize=8.8, color=COLORS["ink"], va="top")

    featured_y = 0.175
    featured_text_y = 0.145
    if period.get("is_synthetic_time"):
        figure.text(
            0.07,
            0.198,
            "Not: Sentetik test PCAP'i - zamanlar yakalama başlangıcına göre göreli gösterilir.",
            fontsize=7.6,
            color=COLORS["muted"],
            va="top",
        )
        featured_y = 0.158
        featured_text_y = 0.130

    alert_dist = report.get("summary", {}).get("alert_type_distribution", {})
    if alert_dist:
        top_text = " | ".join(f"{name}: {count}" for name, count in Counter(alert_dist).most_common(4))
        figure.text(0.07, featured_y, "Öne Çıkan Tespitler", fontsize=10.5, fontweight="bold", color=COLORS["navy"], va="top")
        _draw_wrapped_text(figure, 0.07, featured_text_y, top_text, width=110, fontsize=8.8, color=COLORS["ink"], line_height=0.021, max_lines=2)

    _footer(figure)
    _save_page(pdf, figure)


def _draw_traffic_page(pdf, report):
    figure = _new_figure()
    _page_header(figure, "Trafik Profili", "Protokol dağılımı ve en aktif varlıklar", "2")
    summary = report.get("summary", {})
    protocols = summary.get("protocol_distribution", {})

    ax = figure.add_axes([0.08, 0.55, 0.52, 0.30])
    if protocols:
        ordered = sorted(protocols.items(), key=lambda item: item[1], reverse=True)[:10]
        labels = [item[0] for item in ordered][::-1]
        values = [item[1] for item in ordered][::-1]
        bars = ax.barh(range(len(labels)), values, color=COLORS["blue"])
        ax.set_yticks(range(len(labels)))
        ax.set_yticklabels(labels, fontsize=8)
        ax.set_xlabel("Paket sayısı", fontsize=8)
        ax.tick_params(axis="x", labelsize=8)
        ax.grid(axis="x", alpha=0.15)
        for spine in ax.spines.values():
            spine.set_visible(False)
        for bar, value in zip(bars, values):
            ax.text(value, bar.get_y() + bar.get_height()/2, f" {_fmt_number(value)}", va="center", fontsize=7.5, color=COLORS["ink"])
        ax.set_title("Protokol Dağılımı", loc="left", fontsize=11, fontweight="bold", color=COLORS["navy"])
    else:
        ax.axis("off")
        ax.text(0.0, 0.8, "Protokol verisi bulunamadi.", fontsize=10, color=COLORS["muted"])

    side_x = 0.65
    figure.text(side_x, 0.84, "En Aktif IP'ler", fontsize=10.5, fontweight="bold", color=COLORS["navy"], va="top")
    y = 0.805
    top_ips = summary.get("top_ips", [])[:7]
    if top_ips:
        for index, item in enumerate(top_ips, 1):
            figure.text(side_x, y, f"{index}. {item.get('ip')}  -  {_fmt_number(item.get('packet_references',0))}", fontsize=8.2, color=COLORS["ink"], va="top")
            y -= 0.035
    else:
        figure.text(side_x, y, "IP tabanlı trafik yok.", fontsize=8.5, color=COLORS["muted"], va="top")
        y -= 0.05

    figure.text(side_x, y - 0.01, "Kablosuz Varlıklar", fontsize=10.5, fontweight="bold", color=COLORS["navy"], va="top")
    y -= 0.05
    wireless = summary.get("top_bssids", [])[:4] or summary.get("top_macs", [])[:4]
    if wireless:
        key = "bssid" if summary.get("top_bssids") else "mac"
        for index, item in enumerate(wireless, 1):
            figure.text(side_x, y, f"{index}. {item.get(key)}", fontsize=8.0, color=COLORS["ink"], va="top")
            y -= 0.032
    else:
        figure.text(side_x, y, "Kablosuz MAC/BSSID verisi yok.", fontsize=8.2, color=COLORS["muted"], va="top")

    flow_summary = report.get("flow_summary", {})
    top_flows = flow_summary.get("top_flows", [])[:7]
    if top_flows:
        figure.text(0.08, 0.49, f"En Yoğun Flow'lar  •  Toplam Flow: {flow_summary.get('count', 0)}", fontsize=11, fontweight="bold", color=COLORS["navy"], va="top")
        rows = []
        for item in top_flows:
            src = str(item.get("source_ip") or "-")
            dst = str(item.get("destination_ip") or "-")
            if item.get("source_port") is not None:
                src += f":{item.get('source_port')}"
            if item.get("destination_port") is not None:
                dst += f":{item.get('destination_port')}"
            app = item.get("application_protocol") or item.get("protocol") or "-"
            rows.append([src, dst, str(app), _fmt_number(item.get("packet_count", 0))])
        columns = ["Kaynak", "Hedef", "Uygulama/Protokol", "Paket"]
        widths = [0.30, 0.30, 0.22, 0.10]
    else:
        figure.text(0.08, 0.49, "En Yoğun Bağlantılar", fontsize=11, fontweight="bold", color=COLORS["navy"], va="top")
        connections = summary.get("top_connections", [])[:8]
        rows = []
        for item in connections:
            rows.append([item.get("source_ip", "-"), item.get("destination_ip", "-"), _fmt_number(item.get("packets", 0))])
        if not rows:
            rows = [["-", "-", "IP tabanlı bağlantı bulunamadı"]]
        columns = ["Kaynak", "Hedef", "Paket"]
        widths = [0.38, 0.38, 0.16]

    ax_table = figure.add_axes([0.08, 0.18, 0.84, 0.27])
    ax_table.axis("off")
    table = ax_table.table(cellText=rows, colLabels=columns, loc="upper left", cellLoc="left", colWidths=widths)
    table.auto_set_font_size(False)
    table.set_fontsize(8)
    table.scale(1, 1.35)
    for (row, col), cell in table.get_celld().items():
        cell.set_edgecolor(COLORS["line"])
        cell.set_linewidth(0.5)
        if row == 0:
            cell.set_facecolor(COLORS["navy"])
            cell.get_text().set_color(COLORS["white"])
            cell.get_text().set_fontweight("bold")
        else:
            cell.set_facecolor(COLORS["white"] if row % 2 else COLORS["soft"])

    _footer(figure)
    _save_page(pdf, figure)


def _draw_timeline_page(pdf, report):
    figure = _new_figure()
    _page_header(figure, "Zaman Çizelgesi", "Trafik yoğunluğu ve alarm olaylarinin zaman icindeki görünümü", "3")
    timeline = report.get("timeline", {})
    bins = timeline.get("bins", [])
    alerts = report.get("alerts", [])

    ax = figure.add_axes([0.09, 0.50, 0.82, 0.34])
    if bins:
        x = list(range(len(bins)))
        y = [item.get("packets", 0) for item in bins]
        ax.plot(x, y, linewidth=2.2, color=COLORS["blue"])
        ax.fill_between(x, y, alpha=0.12, color=COLORS["blue"])
        ax.set_ylabel("Paket", fontsize=8)
        ax.set_xlabel("Analiz zamanı (normalize)", fontsize=8)
        ax.tick_params(labelsize=8)
        ax.grid(alpha=0.18)
        for spine in ax.spines.values():
            spine.set_visible(False)

        start = _safe_float(timeline.get("start"))
        end = _safe_float(timeline.get("end"))
        if start is not None and end is not None and end > start:
            for alert in alerts:
                event_time = _safe_float(alert.get("first_seen"))
                if event_time is None or event_time < start or event_time > end:
                    continue
                position = (event_time - start) / (end - start) * max(len(bins) - 1, 1)
                level = _alert_level(alert)
                color = RISK_COLORS.get(level, COLORS["red"])
                ax.axvline(position, color=color, linewidth=1.0, alpha=0.8)
                ax.text(position, max(y) * 0.96 if max(y) else 1, str(alert.get("type", "ALERT")), rotation=90, va="top", ha="right", fontsize=6.5, color=color)
    else:
        ax.axis("off")
        ax.text(0.0, 0.8, "Zaman cizelgesi icin timestamp verisi bulunamadi.", fontsize=10, color=COLORS["muted"])

    figure.text(0.09, 0.43, "Zaman Özeti", fontsize=11, fontweight="bold", color=COLORS["navy"], va="top")
    figure.text(0.09, 0.395, f"Başlangıç: {_fmt_report_timestamp(report, timeline.get('start'))}", fontsize=8.8, color=COLORS["ink"], va="top")
    figure.text(0.09, 0.365, f"Bitiş: {_fmt_report_timestamp(report, timeline.get('end'))}", fontsize=8.8, color=COLORS["ink"], va="top")
    figure.text(0.09, 0.335, f"Toplam süre: {_fmt_duration(timeline.get('duration',0))}", fontsize=8.8, color=COLORS["ink"], va="top")
    if report.get("analysis_period", {}).get("is_synthetic_time"):
        figure.text(0.09, 0.305, "Göreli zaman: 0.000 sn = yakalamanın ilk paketi", fontsize=7.6, color=COLORS["muted"], va="top")

    figure.text(0.52, 0.43, "Alarm Zamanları", fontsize=11, fontweight="bold", color=COLORS["navy"], va="top")
    y_text = 0.395
    for alert in alerts[:9]:
        figure.text(0.52, y_text, f"{_fmt_report_timestamp(report, alert.get('first_seen'))}  {alert.get('type','UNKNOWN')}  [{_alert_level(alert)}]", fontsize=8.0, color=COLORS["ink"], va="top")
        y_text -= 0.031
    if not alerts:
        figure.text(0.52, y_text, "Alarm olayi yok.", fontsize=8.5, color=COLORS["muted"], va="top")

    _footer(figure)
    _save_page(pdf, figure)


def _draw_alert_table_page(pdf, report):
    figure = _new_figure()
    _page_header(figure, "Güvenlik Alarmları", "Tespitlerin öncelik, kaynak ve kanıt özeti", "4")
    alerts = report.get("alerts", [])

    if not alerts:
        box = FancyBboxPatch((0.09, 0.68), 0.82, 0.13, transform=figure.transFigure, boxstyle="round,pad=0.012,rounding_size=0.012", linewidth=0.8, edgecolor=COLORS["line"], facecolor=COLORS["soft"])
        figure.add_artist(box)
        figure.text(0.50, 0.75, "Güvenlik alarmi tespit edilmedi.", fontsize=13, fontweight="bold", color=COLORS["green"], ha="center", va="center")
        _footer(figure)
        _save_page(pdf, figure)
        return

    rows = []
    for index, alert in enumerate(alerts[:18], 1):
        rows.append([
            index,
            alert.get("type", "UNKNOWN"),
            alert.get("derived_level", _alert_level(alert)),
            alert.get("risk_score", 0),
            _confidence_text(alert.get("confidence")),
            _entity(alert, True),
            _entity(alert, False),
            _fmt_number(alert.get("packet_count", 0)),
        ])

    ax_table = figure.add_axes([0.055, 0.24, 0.89, 0.61])
    ax_table.axis("off")
    table = ax_table.table(
        cellText=rows,
        colLabels=["#", "Alarm", "Seviye", "Risk", "Güven", "Kaynak", "Hedef", "Paket"],
        loc="upper left",
        cellLoc="left",
        colWidths=[0.04, 0.17, 0.11, 0.07, 0.08, 0.19, 0.19, 0.09],
    )
    table.auto_set_font_size(False)
    table.set_fontsize(7.2)
    table.scale(1, 1.5)

    for (row, col), cell in table.get_celld().items():
        cell.set_edgecolor(COLORS["line"])
        cell.set_linewidth(0.45)
        if row == 0:
            cell.set_facecolor(COLORS["navy"])
            cell.get_text().set_color(COLORS["white"])
            cell.get_text().set_fontweight("bold")
        else:
            cell.set_facecolor(COLORS["white"] if row % 2 else COLORS["soft"])
            if col == 2:
                level = str(rows[row - 1][2]).upper()
                cell.get_text().set_color(RISK_COLORS.get(level, COLORS["ink"]))
                cell.get_text().set_fontweight("bold")

    if len(alerts) > 18:
        figure.text(0.07, 0.19, f"Not: İlk 18 alarm gosterilmektedir. Toplam alarm sayısı: {len(alerts)}", fontsize=8, color=COLORS["muted"])

    level_dist = report.get("summary", {}).get("alert_level_distribution", {})
    dist_text = " | ".join(f"{level}: {count}" for level, count in level_dist.items())
    figure.text(0.07, 0.16, f"Seviye dağılımı: {dist_text or '-'}", fontsize=8.5, color=COLORS["ink"])

    _footer(figure)
    _save_page(pdf, figure)


def _draw_findings_pages(pdf, report):
    alerts = report.get("alerts", [])
    if not alerts:
        return

    page_number = 5
    for start_index in range(0, len(alerts), 2):
        figure = _new_figure()
        _page_header(figure, "Detaylı Bulgular", "Her alarm icin neden, kapsam ve teknik kanıt", str(page_number))
        page_number += 1

        slots = [(0.09, 0.50), (0.09, 0.12)]
        for slot_index, alert in enumerate(alerts[start_index:start_index + 2]):
            x, y = slots[slot_index]
            h = 0.34
            level = alert.get("derived_level", _alert_level(alert))
            color = RISK_COLORS.get(str(level).upper(), COLORS["muted"])
            box = FancyBboxPatch((x, y), 0.82, h, transform=figure.transFigure, boxstyle="round,pad=0.012,rounding_size=0.012", linewidth=0.8, edgecolor=COLORS["line"], facecolor=COLORS["white"])
            figure.add_artist(box)
            figure.add_artist(Rectangle((x, y + h - 0.055), 0.82, 0.055, transform=figure.transFigure, color=color, linewidth=0))
            figure.text(x + 0.02, y + h - 0.028, f"{start_index + slot_index + 1}. {alert.get('type','UNKNOWN')}", fontsize=11, fontweight="bold", color=COLORS["white"], va="center")
            figure.text(x + 0.79, y + h - 0.028, f"{level} | Risk {alert.get('risk_score',0)} | Güven {_confidence_text(alert.get('confidence'))}", fontsize=8, color=COLORS["white"], ha="right", va="center")

            figure.text(x + 0.02, y + h - 0.083, f"Kaynak: {_entity(alert, True)}", fontsize=8.2, color=COLORS["ink"], va="top")
            figure.text(x + 0.42, y + h - 0.083, f"Hedef: {_entity(alert, False)}", fontsize=8.2, color=COLORS["ink"], va="top")
            figure.text(x + 0.02, y + h - 0.112, f"Paket sayısı: {_fmt_number(alert.get('packet_count',0))}", fontsize=8.2, color=COLORS["ink"], va="top")
            figure.text(x + 0.42, y + h - 0.112, f"İlk görülme: {_fmt_report_timestamp(report, alert.get('first_seen'))}", fontsize=8.2, color=COLORS["ink"], va="top")

            figure.text(x + 0.02, y + h - 0.153, "Tespit nedeni", fontsize=8.4, fontweight="bold", color=COLORS["navy"], va="top")
            next_y = _draw_wrapped_text(figure, x + 0.02, y + h - 0.178, alert.get("reason") or "-", width=100, fontsize=7.9, line_height=0.020, max_lines=3)

            figure.text(x + 0.02, next_y - 0.005, "Teknik kanıt", fontsize=8.4, fontweight="bold", color=COLORS["navy"], va="top")
            evidence_y = next_y - 0.030
            evidence = alert.get("evidence") or []
            if evidence:
                for item in evidence[:4]:
                    wrapped = textwrap.wrap(str(item), width=95)[:2] or [str(item)]
                    figure.text(x + 0.03, evidence_y, "- " + wrapped[0], fontsize=7.3, color=COLORS["ink"], va="top")
                    evidence_y -= 0.018
                    if len(wrapped) > 1:
                        figure.text(x + 0.045, evidence_y, wrapped[1], fontsize=7.3, color=COLORS["ink"], va="top")
                        evidence_y -= 0.018
            else:
                figure.text(x + 0.03, evidence_y, "- Ek kanıt kaydi bulunmuyor.", fontsize=7.3, color=COLORS["muted"], va="top")

        _footer(figure)
        _save_page(pdf, figure)


def _draw_recommendations_page(pdf, report, page_label):
    figure = _new_figure()
    _page_header(figure, "Önerilen Aksiyonlar", "Tespit edilen olaylara göre öncelikli savunma ve inceleme adımları", page_label)
    recommendations = report.get("recommendations", [])

    y = 0.85
    for index, item in enumerate(recommendations[:16], 1):
        level = str(item.get("level", "LOW")).upper()
        color = RISK_COLORS.get(level, COLORS["blue"])
        figure.add_artist(FancyBboxPatch((0.08, y - 0.045), 0.84, 0.058, transform=figure.transFigure, boxstyle="round,pad=0.006,rounding_size=0.008", linewidth=0.5, edgecolor=COLORS["line"], facecolor=COLORS["soft"]))
        figure.add_artist(Rectangle((0.08, y - 0.045), 0.006, 0.058, transform=figure.transFigure, color=color, linewidth=0))
        figure.text(0.10, y, f"{index}. {item.get('alert_type','GENERAL')}", fontsize=8.3, fontweight="bold", color=COLORS["navy"], va="top")
        _draw_wrapped_text(figure, 0.27, y, item.get("text", ""), width=80, fontsize=7.8, line_height=0.018, max_lines=2)
        y -= 0.071
        if y < 0.12:
            break

    figure.text(0.08, 0.125, "İnceleme Notu", fontsize=9.5, fontweight="bold", color=COLORS["navy"], va="top")
    note = (
        "Bu rapor, PCAP/PCAPNG icindeki görülebilir trafik ve uygulamanin kural tabanlı IDS motoru uzerinden otomatik üretilmiştir. "
        "Bir alarm, olay mudahalesi icin güçlü bir sinyal olabilir; ancak nihai karar ağ envanteri, firewall/DNS/authentication loglari ve kurumsal baseline ile korelasyon yapılarak verilmelidir."
    )
    _draw_wrapped_text(figure, 0.08, 0.097, note, width=112, fontsize=7.5, color=COLORS["muted"], line_height=0.017, max_lines=2)
    _footer(figure)
    _save_page(pdf, figure)


def export_pdf(output_path, report_data):
    path = Path(output_path)

    # Older JSON/report_data objects remain compatible: enrich missing fields on the fly.
    if "executive_summary" not in report_data:
        report_data = dict(report_data)
        report_data["executive_summary"] = _build_executive_summary(report_data)
    if "recommendations" not in report_data:
        report_data["recommendations"] = _build_recommendations(report_data.get("alerts", []))
    if "timeline" not in report_data:
        report_data["timeline"] = {"start": None, "end": None, "duration": 0.0, "bins": []}
    if "traffic" not in report_data:
        report_data["traffic"] = {"total_bytes": 0, "average_packet_size": 0.0}

    with PdfPages(path) as pdf:
        _draw_cover_page(pdf, report_data)
        _draw_traffic_page(pdf, report_data)
        _draw_timeline_page(pdf, report_data)
        _draw_alert_table_page(pdf, report_data)
        _draw_findings_pages(pdf, report_data)
        detail_pages = math.ceil(len(report_data.get("alerts", [])) / 2) if report_data.get("alerts") else 0
        _draw_recommendations_page(pdf, report_data, str(5 + detail_pages))

    return path

# =========================================================
# EXCEL / XLSX REPORT EXPORT (standard-library implementation)
# =========================================================

def _xlsx_col_name(index):
    """1-based column number -> Excel column name."""
    result = ""
    while index:
        index, remainder = divmod(index - 1, 26)
        result = chr(65 + remainder) + result
    return result


def _xlsx_xml_escape(value):
    from xml.sax.saxutils import escape

    text = str(value if value is not None else "")
    return escape(text, {'"': '&quot;', "'": '&apos;'})


def _xlsx_cell_xml(row_index, column_index, value, style_id=0):
    reference = f"{_xlsx_col_name(column_index)}{row_index}"
    style = f' s="{style_id}"' if style_id else ""

    if value is None:
        return f'<c r="{reference}"{style}/>'

    if isinstance(value, bool):
        return f'<c r="{reference}" t="b"{style}><v>{1 if value else 0}</v></c>'

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return f'<c r="{reference}"{style}><v>{value}</v></c>'

    text = _xlsx_xml_escape(value)
    return (
        f'<c r="{reference}" t="inlineStr"{style}>'
        f'<is><t xml:space="preserve">{text}</t></is></c>'
    )


def _xlsx_sheet_xml(rows, widths=None, freeze_row=0, auto_filter=None, merges=None):
    max_columns = max(max((len(row) for row in rows), default=1), len(widths or []), 1)
    max_rows = max(len(rows), 1)
    dimension = f"A1:{_xlsx_col_name(max_columns)}{max_rows}"

    columns_xml = ""
    if widths:
        column_items = []
        for index, width in enumerate(widths, start=1):
            column_items.append(
                f'<col min="{index}" max="{index}" width="{float(width):.2f}" customWidth="1"/>'
            )
        columns_xml = f"<cols>{''.join(column_items)}</cols>"

    pane_xml = ""
    if freeze_row and freeze_row > 0:
        top_left = f"A{freeze_row + 1}"
        pane_xml = (
            f'<pane ySplit="{freeze_row}" topLeftCell="{top_left}" '
            'activePane="bottomLeft" state="frozen"/>'
        )

    row_xml = []
    for row_index, row in enumerate(rows, start=1):
        cells = []
        for column_index, item in enumerate(row, start=1):
            if isinstance(item, tuple) and len(item) == 2:
                value, style_id = item
            else:
                value, style_id = item, 0
            cells.append(
                _xlsx_cell_xml(
                    row_index,
                    column_index,
                    value,
                    style_id,
                )
            )
        row_xml.append(f'<row r="{row_index}">{"".join(cells)}</row>')

    auto_filter_xml = f'<autoFilter ref="{auto_filter}"/>' if auto_filter else ""
    merge_xml = ""
    if merges:
        merge_xml = (
            f'<mergeCells count="{len(merges)}">'
            + "".join(f'<mergeCell ref="{_xlsx_xml_escape(item)}"/>' for item in merges)
            + "</mergeCells>"
        )

    return f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <dimension ref="{dimension}"/>
  <sheetViews><sheetView workbookViewId="0">{pane_xml}</sheetView></sheetViews>
  <sheetFormatPr defaultRowHeight="15"/>
  {columns_xml}
  <sheetData>{''.join(row_xml)}</sheetData>
  {auto_filter_xml}
  {merge_xml}
</worksheet>'''


def _xlsx_styles_xml():
    # Style IDs used by export_excel:
    # 0 default, 1 title, 2 section, 3 table header, 4 body,
    # 5 wrapped body, 6 LOW, 7 MEDIUM, 8 HIGH, 9 CRITICAL,
    # 10 KPI label, 11 KPI value, 12 muted/meta, 13 accent header.
    return '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <fonts count="7">
    <font><sz val="11"/><name val="Calibri"/><family val="2"/><scheme val="minor"/></font>
    <font><b/><sz val="16"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font>
    <font><b/><sz val="11"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font>
    <font><b/><sz val="11"/><color rgb="FF0B172A"/><name val="Calibri"/></font>
    <font><b/><sz val="14"/><color rgb="FF0B172A"/><name val="Calibri"/></font>
    <font><sz val="10"/><color rgb="FF64748B"/><name val="Calibri"/></font>
    <font><b/><sz val="12"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font>
  </fonts>
  <fills count="11">
    <fill><patternFill patternType="none"/></fill>
    <fill><patternFill patternType="gray125"/></fill>
    <fill><patternFill patternType="solid"><fgColor rgb="FF0B172A"/><bgColor indexed="64"/></patternFill></fill>
    <fill><patternFill patternType="solid"><fgColor rgb="FF168BCE"/><bgColor indexed="64"/></patternFill></fill>
    <fill><patternFill patternType="solid"><fgColor rgb="FFEAF5FB"/><bgColor indexed="64"/></patternFill></fill>
    <fill><patternFill patternType="solid"><fgColor rgb="FF2DBE7F"/><bgColor indexed="64"/></patternFill></fill>
    <fill><patternFill patternType="solid"><fgColor rgb="FFE0A82E"/><bgColor indexed="64"/></patternFill></fill>
    <fill><patternFill patternType="solid"><fgColor rgb="FFE2782D"/><bgColor indexed="64"/></patternFill></fill>
    <fill><patternFill patternType="solid"><fgColor rgb="FFD94B55"/><bgColor indexed="64"/></patternFill></fill>
    <fill><patternFill patternType="solid"><fgColor rgb="FFF3F6F9"/><bgColor indexed="64"/></patternFill></fill>
    <fill><patternFill patternType="solid"><fgColor rgb="FF12233D"/><bgColor indexed="64"/></patternFill></fill>
  </fills>
  <borders count="2">
    <border><left/><right/><top/><bottom/><diagonal/></border>
    <border>
      <left style="thin"><color rgb="FFD8E1EA"/></left>
      <right style="thin"><color rgb="FFD8E1EA"/></right>
      <top style="thin"><color rgb="FFD8E1EA"/></top>
      <bottom style="thin"><color rgb="FFD8E1EA"/></bottom>
      <diagonal/>
    </border>
  </borders>
  <cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
  <cellXfs count="14">
    <xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>
    <xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"><alignment vertical="center"/></xf>
    <xf numFmtId="0" fontId="2" fillId="3" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1"><alignment vertical="center"/></xf>
    <xf numFmtId="0" fontId="2" fillId="2" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1"><alignment horizontal="center" vertical="center" wrapText="1"/></xf>
    <xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0" applyBorder="1"><alignment vertical="top"/></xf>
    <xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0" applyBorder="1"><alignment vertical="top" wrapText="1"/></xf>
    <xf numFmtId="0" fontId="2" fillId="5" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1"><alignment horizontal="center" vertical="center"/></xf>
    <xf numFmtId="0" fontId="2" fillId="6" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1"><alignment horizontal="center" vertical="center"/></xf>
    <xf numFmtId="0" fontId="2" fillId="7" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1"><alignment horizontal="center" vertical="center"/></xf>
    <xf numFmtId="0" fontId="2" fillId="8" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1"><alignment horizontal="center" vertical="center"/></xf>
    <xf numFmtId="0" fontId="3" fillId="4" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1"><alignment horizontal="center" vertical="center" wrapText="1"/></xf>
    <xf numFmtId="0" fontId="4" fillId="0" borderId="1" xfId="0" applyFont="1" applyBorder="1"><alignment horizontal="center" vertical="center" wrapText="1"/></xf>
    <xf numFmtId="0" fontId="5" fillId="9" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1"><alignment vertical="top" wrapText="1"/></xf>
    <xf numFmtId="0" fontId="6" fillId="10" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1"><alignment vertical="center"/></xf>
  </cellXfs>
  <cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>
</styleSheet>'''


def _xlsx_risk_style(level):
    return {
        "LOW": 6,
        "MEDIUM": 7,
        "HIGH": 8,
        "CRITICAL": 9,
    }.get(str(level or "").upper(), 4)


def _xlsx_alert_time(report_data, value):
    timestamp = _safe_float(value)
    if timestamp is None:
        return "-"

    period = report_data.get("analysis_period", {})
    if period.get("is_synthetic_time") or period.get("time_mode") == "relative":
        start = _safe_float(period.get("first_timestamp"))
        return _fmt_relative_timestamp(timestamp, start)

    return _fmt_timestamp(timestamp)


def _xlsx_rows_for_summary(report_data):
    stats = report_data.get("statistics", {})
    risk = report_data.get("risk", {})
    summary = report_data.get("summary", {})
    period = report_data.get("analysis_period", {})
    traffic = report_data.get("traffic", {})
    alerts = report_data.get("alerts", [])
    flow_summary = report_data.get("flow_summary", {})

    rows = [
        [("NETWORK TRAFFIC ANALYZER & IDS - EXCEL GÜVENLİK RAPORU", 1)],
        [],
        [("Rapor Bilgileri", 2)],
        [("PCAP", 10), (report_data.get("pcap_file_name", "-"), 5), ("Rapor Tarihi", 10), (report_data.get("generated_at", "-"), 5)],
        [("Analiz Başlangıcı", 10), (period.get("first_readable", "-"), 5), ("Analiz Bitişi", 10), (period.get("last_readable", "-"), 5)],
        [("Trafik Süresi", 10), (f"{_safe_float(period.get('duration_seconds')) or 0:.2f} sn", 11), ("Rapor Sürümü", 10), (report_data.get("report_version", "-"), 11)],
        [],
        [("Yönetici Özeti", 2)],
        [(report_data.get("executive_summary", "-"), 5)],
        [],
        [("Güvenlik Durumu", 2)],
        [("Genel Risk", 10), (str(risk.get("level", "LOW")).upper(), _xlsx_risk_style(risk.get("level"))), ("Risk Skoru", 10), (f"{_safe_int(risk.get('score'), 0)}/100", 11)],
        [("Toplam Paket", 10), (_safe_int(stats.get("total_packets"), 0), 11), ("Güvenlik Alarmı", 10), (len(alerts), 11)],
        [("Benzersiz IP", 10), (_safe_int(stats.get("unique_ips"), 0), 11), ("Benzersiz Port", 10), (_safe_int(stats.get("unique_ports"), 0), 11)],
        [("TCP Bağlantısı", 10), (_safe_int(stats.get("tcp_connections"), 0), 11), ("UDP Trafiği", 10), (_safe_int(stats.get("udp_packets"), 0), 11)],
        [("Flow Sayısı", 10), (_safe_int(flow_summary.get("count"), 0), 11), ("Toplam Veri", 10), (f"{_fmt_number(traffic.get('total_bytes', 0))} B", 11)],
        [],
        [("Öne Çıkan Tespitler", 2)],
        [("Alarm Tipi", 3), ("Adet", 3), ("Seviye Dağılımı", 3), ("Adet", 3)],
    ]

    alert_types = list(summary.get("alert_type_distribution", {}).items())
    alert_levels = list(summary.get("alert_level_distribution", {}).items())
    maximum = max(len(alert_types), len(alert_levels), 1)
    for index in range(maximum):
        type_item = alert_types[index] if index < len(alert_types) else ("-", "")
        level_item = alert_levels[index] if index < len(alert_levels) else ("-", "")
        rows.append([
            (type_item[0], 4),
            (type_item[1], 4),
            (level_item[0], _xlsx_risk_style(level_item[0])),
            (level_item[1], 4),
        ])

    if period.get("note"):
        rows.extend([
            [],
            [("Analiz Notu", 2)],
            [(period.get("note"), 12)],
        ])

    return rows


def _xlsx_rows_for_alerts(report_data):
    rows = [[
        ("Alarm Tipi", 3), ("Seviye", 3), ("Risk", 3), ("Güven", 3),
        ("Kaynak", 3), ("Hedef", 3), ("Kaynak Port", 3), ("Hedef Port", 3),
        ("Paket", 3), ("İlk Görülme", 3), ("Son Görülme", 3),
        ("Neden", 3), ("Teknik Kanıt", 3),
    ]]

    for alert in report_data.get("alerts", []):
        level = alert.get("derived_level") or _alert_level(alert)
        evidence = " | ".join(str(item) for item in (alert.get("evidence") or [])) or "-"
        rows.append([
            (alert.get("type", "UNKNOWN"), 4),
            (level, _xlsx_risk_style(level)),
            (_safe_int(alert.get("risk_score"), 0), 4),
            (_confidence_text(alert.get("confidence")), 4),
            (_entity(alert, True), 4),
            (_entity(alert, False), 4),
            (alert.get("source_port") if alert.get("source_port") is not None else "-", 4),
            (alert.get("destination_port") if alert.get("destination_port") is not None else "-", 4),
            (_safe_int(alert.get("packet_count"), 0), 4),
            (_xlsx_alert_time(report_data, alert.get("first_seen")), 4),
            (_xlsx_alert_time(report_data, alert.get("last_seen")), 4),
            (alert.get("reason") or "-", 5),
            (evidence, 5),
        ])

    if len(rows) == 1:
        rows.append([("Güvenlik alarmı tespit edilmedi.", 12)])
    return rows


def _xlsx_rows_for_flows(report_data):
    rows = [[
        ("Protokol", 3), ("Kaynak IP", 3), ("Kaynak Port", 3),
        ("Hedef IP", 3), ("Hedef Port", 3), ("Uygulama Protokolü", 3),
        ("Paket", 3), ("Byte", 3), ("Süre (sn)", 3),
        ("İleri Paket", 3), ("Ters Paket", 3), ("TCP Flags", 3),
    ]]

    for flow in report_data.get("flows", []):
        flags = flow.get("tcp_flags") or []
        if isinstance(flags, (list, tuple, set)):
            flags = ", ".join(str(item) for item in flags)
        rows.append([
            (flow.get("protocol") or "-", 4),
            (flow.get("source_ip") or "-", 4),
            (flow.get("source_port") if flow.get("source_port") is not None else "-", 4),
            (flow.get("destination_ip") or "-", 4),
            (flow.get("destination_port") if flow.get("destination_port") is not None else "-", 4),
            (flow.get("application_protocol") or flow.get("protocol") or "-", 4),
            (_safe_int(flow.get("packet_count"), 0), 4),
            (_safe_int(flow.get("byte_count"), 0), 4),
            (round(_safe_float(flow.get("duration")) or 0.0, 6), 4),
            (_safe_int(flow.get("forward_packets"), 0), 4),
            (_safe_int(flow.get("reverse_packets"), 0), 4),
            (flags or "-", 5),
        ])

    if len(rows) == 1:
        rows.append([("IP tabanlı flow kaydı bulunamadı.", 12)])
    return rows


def _xlsx_rows_for_protocols(report_data):
    summary = report_data.get("summary", {})
    rows = [[("Protokol", 3), ("Paket Sayısı", 3), ("Kategori", 3)]]
    for protocol, count in sorted(summary.get("protocol_distribution", {}).items(), key=lambda item: item[1], reverse=True):
        rows.append([(protocol, 4), (count, 4), ("Network / Transport", 4)])
    for protocol, count in sorted(summary.get("application_protocol_distribution", {}).items(), key=lambda item: item[1], reverse=True):
        rows.append([(protocol, 4), (count, 4), ("Application", 4)])
    if len(rows) == 1:
        rows.append([("Protokol verisi bulunamadı.", 12)])
    return rows


def _xlsx_rows_for_assets(report_data):
    summary = report_data.get("summary", {})
    rows = [[("Varlık Türü", 3), ("Değer", 3), ("Paket Referansı", 3)]]
    mappings = [
        ("IP", "top_ips", "ip"),
        ("MAC", "top_macs", "mac"),
        ("BSSID", "top_bssids", "bssid"),
        ("SSID", "top_ssids", "ssid"),
        ("PORT", "top_ports", "port"),
    ]
    for label, key, value_key in mappings:
        for item in summary.get(key, []):
            rows.append([
                (label, 4),
                (item.get(value_key, "-"), 4),
                (_safe_int(item.get("packet_references"), 0), 4),
            ])
    if len(rows) == 1:
        rows.append([("Varlık bilgisi bulunamadı.", 12)])
    return rows


def _xlsx_rows_for_connections(report_data):
    rows = [[("Kaynak IP", 3), ("Hedef IP", 3), ("Paket", 3)]]
    for item in report_data.get("summary", {}).get("top_connections", []):
        rows.append([
            (item.get("source_ip") or "-", 4),
            (item.get("destination_ip") or "-", 4),
            (_safe_int(item.get("packets"), 0), 4),
        ])
    if len(rows) == 1:
        rows.append([("IP bağlantı bilgisi bulunamadı.", 12)])
    return rows


def _xlsx_rows_for_recommendations(report_data):
    rows = [[("Alarm Tipi", 3), ("Seviye", 3), ("Önerilen Aksiyon", 3)]]
    for item in report_data.get("recommendations", []):
        level = item.get("level", "LOW")
        rows.append([
            (item.get("alert_type", "GENERAL"), 4),
            (level, _xlsx_risk_style(level)),
            (item.get("text") or "-", 5),
        ])
    if len(rows) == 1:
        rows.append([("GENERAL", 4), ("LOW", 6), ("Analiz sonuçlarını ağ baseline'ı ve diğer log kaynaklarıyla korele edin.", 5)])
    return rows


def _xlsx_rows_for_packets(report_data):
    headers = [
        "Zaman", "Kaynak IP", "Hedef IP", "Kaynak Port", "Hedef Port",
        "Protokol", "Uygulama", "Paket Boyutu", "TCP Flags", "DNS Query",
        "Kaynak MAC", "Hedef MAC", "SSID", "BSSID", "WLAN Subtype",
        "EAPOL Key", "Replay Counter",
    ]
    rows = [[(header, 3) for header in headers]]
    for packet in report_data.get("packet_sample", []):
        rows.append([
            (_xlsx_alert_time(report_data, packet.get("timestamp")), 4),
            (packet.get("src_ip") or "-", 4),
            (packet.get("dst_ip") or "-", 4),
            (packet.get("src_port") if packet.get("src_port") is not None else "-", 4),
            (packet.get("dst_port") if packet.get("dst_port") is not None else "-", 4),
            (packet.get("protocol") or "-", 4),
            (packet.get("application_protocol") or "-", 4),
            (_safe_int(packet.get("packet_size"), 0), 4),
            (packet.get("tcp_flags") or "-", 4),
            (packet.get("dns_query") or "-", 5),
            (packet.get("src_mac") or "-", 4),
            (packet.get("dst_mac") or "-", 4),
            (packet.get("ssid") or "-", 4),
            (packet.get("bssid") or "-", 4),
            (packet.get("wlan_subtype") if packet.get("wlan_subtype") is not None else "-", 4),
            (packet.get("eapol_key_number") if packet.get("eapol_key_number") is not None else "-", 4),
            (packet.get("eapol_replay_counter") if packet.get("eapol_replay_counter") is not None else "-", 4),
        ])
    return rows


def export_excel(output_path, report_data):
    """
    Create a multi-sheet professional .xlsx IDS report without adding a new
    third-party dependency to the desktop application.
    """
    from zipfile import ZIP_DEFLATED, ZipFile

    path = Path(output_path)
    if path.suffix.lower() != ".xlsx":
        path = path.with_suffix(".xlsx")

    # Older report-data dictionaries remain compatible.
    data = dict(report_data or {})
    if "executive_summary" not in data:
        data["executive_summary"] = _build_executive_summary(data)
    if "recommendations" not in data:
        data["recommendations"] = _build_recommendations(data.get("alerts", []))
    data.setdefault("summary", {})
    data.setdefault("analysis_period", {})
    data.setdefault("traffic", {})
    data.setdefault("flow_summary", {})
    data.setdefault("flows", [])
    data.setdefault("packet_sample", [])

    sheets = [
        {
            "name": "Özet",
            "rows": _xlsx_rows_for_summary(data),
            "widths": [22, 26, 22, 26, 18, 18, 18, 18],
            "freeze": 0,
            "filter": None,
            "merges": ["A1:H2", "A3:H3", "A8:H8", "A9:H9", "A11:H11", "A18:H18", "A24:H24", "A25:H25"],
        },
        {
            "name": "Alarmlar",
            "rows": _xlsx_rows_for_alerts(data),
            "widths": [20, 13, 10, 11, 22, 22, 12, 12, 10, 20, 20, 55, 65],
            "freeze": 1,
            "filter": None,
            "merges": [],
        },
        {
            "name": "Akışlar",
            "rows": _xlsx_rows_for_flows(data),
            "widths": [12, 20, 12, 20, 12, 20, 10, 12, 12, 12, 12, 28],
            "freeze": 1,
            "filter": None,
            "merges": [],
        },
        {
            "name": "Protokoller",
            "rows": _xlsx_rows_for_protocols(data),
            "widths": [24, 16, 24],
            "freeze": 1,
            "filter": None,
            "merges": [],
        },
        {
            "name": "Varlıklar",
            "rows": _xlsx_rows_for_assets(data),
            "widths": [18, 36, 18],
            "freeze": 1,
            "filter": None,
            "merges": [],
        },
        {
            "name": "Bağlantılar",
            "rows": _xlsx_rows_for_connections(data),
            "widths": [24, 24, 14],
            "freeze": 1,
            "filter": None,
            "merges": [],
        },
        {
            "name": "Öneriler",
            "rows": _xlsx_rows_for_recommendations(data),
            "widths": [22, 14, 90],
            "freeze": 1,
            "filter": None,
            "merges": [],
        },
        {
            "name": "Paket Örneği",
            "rows": _xlsx_rows_for_packets(data),
            "widths": [20, 18, 18, 12, 12, 13, 16, 13, 14, 42, 20, 20, 25, 20, 14, 14, 18],
            "freeze": 1,
            "filter": None,
            "merges": [],
        },
    ]

    # Apply filters to regular table sheets when there is at least one data row.
    for sheet in sheets[1:]:
        if len(sheet["rows"]) > 1:
            last_col = _xlsx_col_name(max(len(row) for row in sheet["rows"]))
            sheet["filter"] = f"A1:{last_col}{len(sheet['rows'])}"

    now = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

    content_types = [
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">',
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>',
        '<Default Extension="xml" ContentType="application/xml"/>',
        '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>',
        '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>',
        '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>',
        '<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>',
    ]
    for index in range(1, len(sheets) + 1):
        content_types.append(
            f'<Override PartName="/xl/worksheets/sheet{index}.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        )
    content_types.append('</Types>')

    workbook_sheets = []
    workbook_rels = []
    for index, sheet in enumerate(sheets, start=1):
        workbook_sheets.append(
            f'<sheet name="{_xlsx_xml_escape(sheet["name"])}" sheetId="{index}" r:id="rId{index}"/>'
        )
        workbook_rels.append(
            f'<Relationship Id="rId{index}" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
            f'Target="worksheets/sheet{index}.xml"/>'
        )
    workbook_rels.append(
        f'<Relationship Id="rId{len(sheets) + 1}" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" '
        'Target="styles.xml"/>'
    )

    root_rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
  <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>
</Relationships>'''

    workbook_xml = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
 xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <bookViews><workbookView activeTab="0"/></bookViews>
  <sheets>{''.join(workbook_sheets)}</sheets>
</workbook>'''

    workbook_rels_xml = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  {''.join(workbook_rels)}
</Relationships>'''

    core_xml = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
 xmlns:dc="http://purl.org/dc/elements/1.1/"
 xmlns:dcterms="http://purl.org/dc/terms/"
 xmlns:dcmitype="http://purl.org/dc/dcmitype/"
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <dc:creator>Network Traffic Analyzer &amp; IDS</dc:creator>
  <cp:lastModifiedBy>Network Traffic Analyzer &amp; IDS</cp:lastModifiedBy>
  <dcterms:created xsi:type="dcterms:W3CDTF">{now}</dcterms:created>
  <dcterms:modified xsi:type="dcterms:W3CDTF">{now}</dcterms:modified>
  <dc:title>IDS Security Analysis Report</dc:title>
</cp:coreProperties>'''

    app_xml = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"
 xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">
  <Application>Network Traffic Analyzer &amp; IDS</Application>
  <Sheets>{len(sheets)}</Sheets>
</Properties>'''

    with ZipFile(path, "w", ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", "".join(content_types))
        archive.writestr("_rels/.rels", root_rels)
        archive.writestr("docProps/core.xml", core_xml)
        archive.writestr("docProps/app.xml", app_xml)
        archive.writestr("xl/workbook.xml", workbook_xml)
        archive.writestr("xl/_rels/workbook.xml.rels", workbook_rels_xml)
        archive.writestr("xl/styles.xml", _xlsx_styles_xml())

        for index, sheet in enumerate(sheets, start=1):
            archive.writestr(
                f"xl/worksheets/sheet{index}.xml",
                _xlsx_sheet_xml(
                    sheet["rows"],
                    widths=sheet["widths"],
                    freeze_row=sheet["freeze"],
                    auto_filter=sheet["filter"],
                    merges=sheet["merges"],
                ),
            )

    return path

