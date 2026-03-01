#!/usr/bin/env python3
"""
ReportGC Demo - Run the security reporting pipeline with sample data
"""

import json
import sys
from pathlib import Path
from datetime import datetime

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

from engine import SecurityExplainPlan, Finding, RiskLevel
from pptx_generator import PPTXGenerator

# ==========================================
# Sample Data Factory (for demo purposes)
# ==========================================

def create_sample_finding(
    id: str = "CVE-2023-1234",
    title: str = "Test Vulnerability",
    severity: str = "HIGH",
    cvss_score: float = 7.5,
    cisa_kev: bool = False,
    fixed_version: str = "1.2.3",
    pkg_name: str = "test-package",
    installed_version: str = "1.0.0",
    description: str = "Test description"
) -> Finding:
    return Finding(
        id=id,
        title=title,
        severity=severity,
        cvss_score=cvss_score,
        cisa_kev=cisa_kev,
        fixed_version=fixed_version,
        pkg_name=pkg_name,
        installed_version=installed_version,
        description=description
    )


def create_sample_trivy_vulnerability(
    vuln_id: str = "CVE-2023-1234",
    title: str = "Test Vuln",
    severity: str = "HIGH",
    cvss_score: float = 7.5,
    fixed_version: str = "1.2.3",
    pkg_name: str = "test-pkg",
    installed_version: str = "1.0.0",
    description: str = "Test desc"
) -> dict:
    return {
        "VulnerabilityID": vuln_id,
        "Title": title,
        "Severity": severity,
        "CVSS": {"nvd": {"V3Score": cvss_score}},
        "FixedVersion": fixed_version,
        "PkgName": pkg_name,
        "InstalledVersion": installed_version,
        "Description": description,
        "CisaKnownExploited": False
    }


def create_sample_trivy_scan():
    """Create a realistic sample Trivy scan with various vulnerability levels"""
    vulnerabilities = [
        # Critical (FULL_TABLE_SCAN)
        create_sample_trivy_vulnerability(
            vuln_id="CVE-2024-0001",
            title="Unauthenticated RCE in OpenSSL",
            severity="CRITICAL",
            cvss_score=9.8,
            pkg_name="openssl",
            installed_version="1.1.1",
            fixed_version="1.1.1w"
        ),
        create_sample_trivy_vulnerability(
            vuln_id="CVE-2024-0002",
            title="Buffer overflow in kernel module",
            severity="CRITICAL",
            cvss_score=9.2,
            pkg_name="kernel",
            installed_version="5.10.0",
            fixed_version="5.10.209"
        ),
        # High (INDEX_RANGE_SCAN)
        create_sample_trivy_vulnerability(
            vuln_id="CVE-2024-0003",
            title="SQL Injection in Django ORM",
            severity="HIGH",
            cvss_score=8.1,
            pkg_name="django",
            installed_version="3.2.0",
            fixed_version="3.2.23"
        ),
        create_sample_trivy_vulnerability(
            vuln_id="CVE-2024-0004",
            title="Privilege escalation in sudo",
            severity="HIGH",
            cvss_score=7.8,
            pkg_name="sudo",
            installed_version="1.9.9",
            fixed_version="1.9.13"
        ),
        # Medium (NESTED_LOOP)
        create_sample_trivy_vulnerability(
            vuln_id="CVE-2024-0005",
            title="XSS vulnerability in front-end library",
            severity="MEDIUM",
            cvss_score=5.3,
            pkg_name="react",
            installed_version="17.0.0",
            fixed_version="17.0.2"
        ),
        # Low (SEQUENTIAL_READ)
        create_sample_trivy_vulnerability(
            vuln_id="CVE-2024-0006",
            title="Information disclosure in debug mode",
            severity="LOW",
            cvss_score=2.7,
            pkg_name="flask",
            installed_version="2.0.0",
            fixed_version="2.0.3"
        ),
    ]
    
    return {
        "Results": [
            {
                "Target": "python-app:latest",
                "Class": "lang-pkgs",
                "Type": "pip",
                "Vulnerabilities": vulnerabilities
            }
        ]
    }


# ==========================================
# Main Demo
# ==========================================

def main():
    print("\n" + "="*70)
    print("ReportGC - Security Reporting Pipeline Demo")
    print("="*70 + "\n")
    
    # Step 1: Create sample Trivy scan data
    print("[1] Creating sample vulnerability scan data...")
    scan_data = create_sample_trivy_scan()
    print(f"    ✓ Created scan with {len(scan_data['Results'][0]['Vulnerabilities'])} vulnerabilities\n")
    
    # Step 2: Process through SecurityExplainPlan engine
    print("[2] Processing through SecurityExplainPlan engine...")
    try:
        engine = SecurityExplainPlan(scan_data)
        print(f"    ✓ Parsed {len(engine.findings)} findings\n")
    except Exception as e:
        print(f"    ✗ Engine failed: {e}")
        return False
    
    # Step 3: Generate explain plan output
    print("[3] Generating Security Explain Plan...")
    try:
        plan_data = engine.to_dict()
        print(f"    Grade: {plan_data['grade']}")
        print(f"    Total Findings: {plan_data['summary']['total_findings']}")
        print(f"    Critical (FULL_TABLE_SCAN): {plan_data['execution_plan']['full_table_scans']['count']}")
        print(f"    High (INDEX_RANGE_SCAN): {plan_data['execution_plan']['index_scans']['count']}")
        print(f"    Medium (NESTED_LOOP): {plan_data['execution_plan']['nested_loops']['count']}")
        print(f"    Low (SEQUENTIAL_READ): {plan_data['execution_plan']['low_priority']['count']}")
        print(f"    Total Effort Hours: {plan_data['total_effort_hours']}h\n")
    except Exception as e:
        print(f"    ✗ Plan generation failed: {e}")
        return False
    
    # Step 4: Generate PPTX presentation
    print("[4] Generating PowerPoint presentation...")
    try:
        pptx_gen = PPTXGenerator()
        output_dir = Path(tempfile.gettempdir()) / "reportgc_demo"
        output_dir.mkdir(exist_ok=True)
        report_id = plan_data['report_id']
        pptx_path = output_dir / f"ReportGC-{report_id}.pptx"
        pptx_gen.generate_pptx(plan_data, str(pptx_path))
        print(f"    ✓ Generated: {pptx_path}\n")
    except Exception as e:
        print(f"    ✗ PPTX generation failed: {e}\n")
        # Continue anyway since report_generator needs WeasyPrint
    
    # Step 5: Display detailed findings
    print("[5] Detailed Risk Assessment:\n")
    
    print("    CRITICAL FINDINGS (FULL_TABLE_SCAN - Immediate Action Required):")
    for item in plan_data['execution_plan']['full_table_scans']['items'][:3]:
        print(f"      • {item['id']}: {item['title']}")
        print(f"        Package: {item['pkg_name']} {item['installed_version']} → {item['fixed_version']}")
        print(f"        Est. Effort: {item['fix_effort_hours']}h\n")
    
    print("    HIGH FINDINGS (INDEX_RANGE_SCAN - Next Sprint):")
    for item in plan_data['execution_plan']['index_scans']['items']:
        print(f"      • {item['id']}: {item['title']}")
        print(f"        CVSS Score: {item['cvss_score']}")
        print(f"        Est. Effort: {item['fix_effort_hours']}h\n")
    
    # Step 6: Summary
    print("="*70)
    print("SUMMARY")
    print("="*70)
    print(f"Report ID: {plan_data['report_id']}")
    print(f"Generated: {plan_data['generated_at']}")
    print(f"Total Remediations Needed: {plan_data['total_effort_hours']} hours")
    print(f"Overall Grade: {plan_data['grade']}")
    print("\nRecommendation:")
    
    grade = plan_data['grade']
    if grade == 'A':
        print("  ✓ Excellent security posture - maintain current practices")
    elif grade == 'B':
        print("  ⚠ Good posture - prioritize critical findings")
    elif grade == 'C':
        print("  ⚠ Concerning - multiple high-risk issues need attention")
    elif grade == 'D':
        print("  ✗ Poor - significant security debt")
    else:
        print("  ✗ Critical - immediate remediation required")
    
    print("\n" + "="*70 + "\n")
    return True


if __name__ == "__main__":
    import tempfile
    success = main()
    sys.exit(0 if success else 1)
