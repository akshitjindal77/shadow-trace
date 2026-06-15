"""
ShadowTrace Report Generator

Generates PDF reports from scan results using HTML templates and WeasyPrint.
"""
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Dict
from fastapi.responses import FileResponse
from jinja2 import Environment, FileSystemLoader, select_autoescape

try:
    stderr_fd = os.dup(2)
    with tempfile.TemporaryFile() as tmp:
        os.dup2(tmp.fileno(), 2)
        try:
            from weasyprint import HTML
            HAS_WEASYPRINT = True
        except Exception:
            HTML = None  # type: ignore
            HAS_WEASYPRINT = False
        finally:
            os.dup2(stderr_fd, 2)
            os.close(stderr_fd)
except Exception:
    HTML = None  # type: ignore
    HAS_WEASYPRINT = False

BASE_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = BASE_DIR / "reports"
TEMPLATES_DIR = BASE_DIR / "templates"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)


def _load_json(value: str, fallback: Any) -> Any:
    try:
        return json.loads(value)
    except Exception:
        return fallback


def _normalize_platforms(findings: Dict[str, Any]) -> list:
    platforms = _load_json(findings.get("findings_json", "{}")) if isinstance(findings, dict) else {}
    username_enum = platforms.get("username_enum", {}).get("data", {}) if isinstance(platforms, dict) else {}
    return [item for item in username_enum.get("platforms", []) if item.get("found")]


def _normalize_breaches(findings: Dict[str, Any]) -> list:
    platforms = _load_json(findings.get("findings_json", "{}")) if isinstance(findings, dict) else {}
    breaches_data = platforms.get("breaches", {}).get("data", {}) if isinstance(platforms, dict) else {}
    return breaches_data.get("breaches", []) or breaches_data.get("items", []) or []


def _normalize_dorks(findings: Dict[str, Any]) -> list:
    platforms = _load_json(findings.get("findings_json", "{}")) if isinstance(findings, dict) else {}
    dorks_data = platforms.get("dorks", {}).get("data", {}) if isinstance(platforms, dict) else {}
    return dorks_data.get("queries", []) or []


def pdf_path_for_scan(scan_id: str) -> Path:
    return REPORTS_DIR / f"shadowtrace_{scan_id}.pdf"


def _template_context(scan_result: Any) -> Dict[str, Any]:
    findings = _load_json(scan_result.findings_json) if hasattr(scan_result, "findings_json") else {}
    recommendations = _load_json(scan_result.recommendations_json) if hasattr(scan_result, "recommendations_json") else []

    username_enum = findings.get("username_enum", {}).get("data", {}) if isinstance(findings, dict) else {}
    breach_data = findings.get("breaches", {}).get("data", {}) if isinstance(findings, dict) else {}
    dork_data = findings.get("dorks", {}).get("data", {}) if isinstance(findings, dict) else {}

    return {
        "scan_id": scan_result.scan_id,
        "input_value": scan_result.input_value,
        "input_type": scan_result.input_type,
        "scan_timestamp": scan_result.scan_timestamp,
        "overall_risk_score": scan_result.overall_risk_score,
        "risk_level": scan_result.risk_level,
        "breach_count": scan_result.breach_count,
        "platforms_found": scan_result.platforms_found,
        "dork_results_count": scan_result.dork_results_count,
        "scan_duration_seconds": scan_result.scan_duration_seconds,
        "recommendations": recommendations,
        "platforms": username_enum.get("platforms", []),
        "breaches": breach_data.get("breaches", []) or breach_data.get("items", []),
        "dorks": dork_data.get("queries", []),
        "raw_findings": findings,
    }


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
        recommendations = _load_json(scan_result.recommendations_json)
    except Exception:
        recommendations = []

    for item in recommendations:
        action = item.get("action") if isinstance(item, dict) else str(item)
        reason = item.get("reason") if isinstance(item, dict) else ""
        report.append(f"- {action}: {reason}")

    report.append("\nFindings:")
    try:
        findings = _load_json(scan_result.findings_json)
    except Exception:
        findings = {}
    report.append(json.dumps(findings, indent=2)[:4000])
    return "\n".join(report)


def generate_pdf_report(scan_result: Any) -> FileResponse:
    pdf_path = pdf_path_for_scan(scan_result.scan_id)
    if HAS_WEASYPRINT:
        env = Environment(
            loader=FileSystemLoader(str(TEMPLATES_DIR)),
            autoescape=select_autoescape(["html", "xml"]),
        )
        template = env.get_template("report_template.html")
        html_content = template.render(_template_context(scan_result))
        HTML(string=html_content).write_pdf(str(pdf_path))
    else:
        text_content = _build_report_content(scan_result)
        pdf_bytes = _simple_pdf_bytes(text_content)
        with open(pdf_path, "wb") as file:
            file.write(pdf_bytes)
    return FileResponse(str(pdf_path), media_type="application/pdf", filename=pdf_path.name)
