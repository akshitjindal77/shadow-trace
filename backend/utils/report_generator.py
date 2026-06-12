"""
ShadowTrace Report Generator

Generates basic PDF reports from scan results.
"""
import json
from pathlib import Path
from typing import Any
from fastapi.responses import FileResponse

BASE_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = BASE_DIR / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def _escape_pdf_string(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _simple_pdf_bytes(text: str) -> bytes:
    content_string = _escape_pdf_string(text)
    stream = f"BT /F1 12 Tf 50 760 Td ({content_string}) Tj ET".encode("latin-1", errors="replace")
    stream_length = len(stream)

    objects = [
        (1, b"<< /Type /Catalog /Pages 2 0 R >>"),
        (2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>"),
        (
            3,
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
        ),
        (4, f"<< /Length {stream_length} >>\nstream\n".encode("latin-1") + stream + b"\nendstream"),
        (5, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"),
    ]

    pdf = bytearray()
    pdf.extend(b"%PDF-1.4\n")
    offsets = []

    for obj_id, obj_body in objects:
        offsets.append(len(pdf))
        pdf.extend(f"{obj_id} 0 obj\n".encode("latin-1"))
        pdf.extend(obj_body)
        pdf.extend(b"\nendobj\n")

    xref_start = len(pdf)
    pdf.extend(f"xref\n0 {len(objects) + 1}\n".encode("latin-1"))
    pdf.extend(b"0000000000 65535 f \n")
    for offset in offsets:
        pdf.extend(f"{offset:010d} 00000 n \n".encode("latin-1"))
    pdf.extend(b"trailer\n")
    pdf.extend(f"<< /Size {len(objects) + 1} /Root 1 0 R >>\n".encode("latin-1"))
    pdf.extend(b"startxref\n")
    pdf.extend(f"{xref_start}\n".encode("latin-1"))
    pdf.extend(b"%%EOF")

    return bytes(pdf)


def _build_report_content(scan_result: Any) -> str:
    report = [
        f"ShadowTrace Report",
        f"Scan ID: {scan_result.scan_id}",
        f"Input Value: {scan_result.input_value}",
        f"Input Type: {scan_result.input_type}",
        f"Scan Timestamp: {scan_result.scan_timestamp}",
        f"Overall Risk Score: {scan_result.overall_risk_score}",
        f"Risk Level: {scan_result.risk_level}",
        f"Breach Count: {scan_result.breach_count}",
        f"Platforms Found: {scan_result.platforms_found}",
        f"Dork Results Count: {scan_result.dork_results_count}",
        f"Scan Duration (s): {scan_result.scan_duration_seconds}",
        "\nRecommendations:",
    ]

    try:
        recommendations = json.loads(scan_result.recommendations_json)
    except Exception:
        recommendations = []

    for item in recommendations:
        action = item.get("action") if isinstance(item, dict) else str(item)
        reason = item.get("reason") if isinstance(item, dict) else ""
        report.append(f"- {action}: {reason}")

    report.append("\nFindings:")
    try:
        findings = json.loads(scan_result.findings_json)
    except Exception:
        findings = {}
    report.append(json.dumps(findings, indent=2)[:4000])
    return "\n".join(report)


def pdf_path_for_scan(scan_id: str) -> Path:
    return REPORTS_DIR / f"shadowtrace_{scan_id}.pdf"


def generate_pdf_report(scan_result: Any) -> FileResponse:
    pdf_path = pdf_path_for_scan(scan_result.scan_id)
    if not pdf_path.exists():
        content = _build_report_content(scan_result)
        pdf_bytes = _simple_pdf_bytes(content)
        with open(pdf_path, "wb") as file:
            file.write(pdf_bytes)
    return FileResponse(str(pdf_path), media_type="application/pdf", filename=pdf_path.name)
