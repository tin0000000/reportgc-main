"""
ReportGC Application Launcher
Runs the full application with sample API requests
"""

import asyncio
import json
from pathlib import Path
import sys

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

from engine import SecurityExplainPlan
from pptx_generator import PPTXGenerator


def create_sample_trivy_scan():
    """Create realistic sample vulnerability data"""
    return {
        "Results": [
            {
                "Target": "app:latest",
                "Type": "pip",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-0001",
                        "Title": "Unauthenticated RCE in OpenSSL",
                        "Severity": "CRITICAL",
                        "CVSS": {"nvd": {"V3Score": 9.8}},
                        "FixedVersion": "1.1.1w",
                        "PkgName": "openssl",
                        "InstalledVersion": "1.1.1",
                        "Description": "Critical vulnerability in SSL/TLS encryption",
                        "CisaKnownExploited": True
                    },
                    {
                        "VulnerabilityID": "CVE-2024-0002",
                        "Title": "Buffer overflow in kernel",
                        "Severity": "CRITICAL",
                        "CVSS": {"nvd": {"V3Score": 9.2}},
                        "FixedVersion": "5.10.209",
                        "PkgName": "kernel",
                        "InstalledVersion": "5.10.0",
                        "Description": "Kernel memory corruption",
                        "CisaKnownExploited": False
                    },
                    {
                        "VulnerabilityID": "CVE-2024-0003",
                        "Title": "SQL Injection in Django",
                        "Severity": "HIGH",
                        "CVSS": {"nvd": {"V3Score": 8.1}},
                        "FixedVersion": "3.2.23",
                        "PkgName": "django",
                        "InstalledVersion": "3.2.0",
                        "Description": "SQL injection in ORM",
                        "CisaKnownExploited": False
                    },
                    {
                        "VulnerabilityID": "CVE-2024-0004",
                        "Title": "XSS in React",
                        "Severity": "MEDIUM",
                        "CVSS": {"nvd": {"V3Score": 5.3}},
                        "FixedVersion": "17.0.2",
                        "PkgName": "react",
                        "InstalledVersion": "17.0.0",
                        "Description": "Cross-site scripting vulnerability",
                        "CisaKnownExploited": False
                    },
                ]
            }
        ]
    }


def main():
    print("\n" + "="*80)
    print("🚀 ReportGC - Full Application Demo")
    print("="*80 + "\n")
    
    # Test 1: Engine Processing
    print("📊 TEST 1: SecurityExplainPlan Engine\n")
    print("-" * 80)
    
    scan_data = create_sample_trivy_scan()
    
    print(f"Input: {len(scan_data['Results'][0]['Vulnerabilities'])} vulnerabilities")
    
    try:
        engine = SecurityExplainPlan(scan_data)
        plan_data = engine.to_dict()
        
        print(f"✅ Engine processed successfully\n")
        print(f"   Grade: {plan_data['grade']}")
        print(f"   Total Findings: {plan_data['summary']['total_findings']}")
        print(f"   Critical: {plan_data['summary']['critical']}")
        print(f"   High: {plan_data['summary']['high']}")
        print(f"   Medium: {plan_data['summary']['medium']}")
        print(f"   Low: {plan_data['summary']['low']}")
        print(f"   Total Effort: {plan_data.get('total_effort_hours', 0)}h")
        print(f"   CISA KEV: {plan_data['summary']['cisa_kev_count']}")
        
    except Exception as e:
        print(f"❌ Engine failed: {e}")
        return False
    
    # Test 2: PPTX Generation
    print(f"\n📊 TEST 2: PowerPoint Generation\n")
    print("-" * 80)
    
    try:
        pptx_gen = PPTXGenerator()
        output_dir = Path("/tmp") if sys.platform != "win32" else Path.home() / "AppData/Local/Temp"
        output_dir = output_dir / "reportgc_demo"
        output_dir.mkdir(exist_ok=True)
        
        pptx_path = output_dir / f"ReportGC-{plan_data['report_id']}.pptx"
        pptx_gen.generate_pptx(plan_data, str(pptx_path))
        
        file_size_mb = pptx_path.stat().st_size / (1024 * 1024)
        print(f"✅ PPTX generated successfully")
        print(f"   Path: {pptx_path}")
        print(f"   Size: {file_size_mb:.2f} MB")
        
    except Exception as e:
        print(f"❌ PPTX generation failed: {e}")
        return False
    
    # Test 3: API Simulation
    print(f"\n📊 TEST 3: API Endpoint Simulation\n")
    print("-" * 80)
    
    endpoints = {
        "/health": "Health check",
        "/api/validate": "Validate scan format",
        "/api/report": "Generate PPTX report",
        "/api/report/metadata": "Get metadata only",
        "/api/upload": "Upload JSON file",
    }
    
    print("Available API Endpoints:\n")
    for endpoint, description in endpoints.items():
        print(f"  📍 {endpoint:<25} - {description}")
    
    # Test 4: Detailed Report
    print(f"\n📊 TEST 4: Executive Summary\n")
    print("-" * 80)
    
    print(f"Report ID: {plan_data['report_id']}")
    print(f"Generated: {plan_data['generated_at']}\n")
    
    print("🔴 CRITICAL FINDINGS (Immediate Action Required):")
    for item in plan_data['execution_plan']['full_table_scans']['items']:
        print(f"   • {item['id']}: {item['title']}")
        print(f"     Package: {item['pkg_name']} {item['installed_version']} → {item['fixed_version']}")
        print(f"     Est. Effort: {item['fix_effort_hours']}h")
        print(f"     CVSS: {item['cvss_score']}\n")
    
    print("🟠 HIGH SEVERITY (Next Sprint):")
    for item in plan_data['execution_plan']['index_scans']['items']:
        print(f"   • {item['id']}: {item['title']}")
        print(f"     CVSS: {item['cvss_score']}")
        print(f"     Est. Effort: {item['fix_effort_hours']}h\n")
    
    if plan_data['execution_plan']['nested_loops']['items']:
        print("🟡 MEDIUM SEVERITY (Sprint +1):")
        for item in plan_data['execution_plan']['nested_loops']['items']:
            print(f"   • {item['id']}: {item['title']}")
            print(f"     CVSS: {item['cvss_score']}\n")
    
    # Summary
    print("="*80)
    print("💼 EXECUTIVE SUMMARY")
    print("="*80)
    
    grade = plan_data['grade']
    grade_meanings = {
        'A': '✅ Excellent - Strong security posture',
        'B': '⚠️  Good - Address critical findings',
        'C': '⚠️  Concerning - Multiple high-risk issues',
        'D': '❌ Poor - Significant security debt',
        'F': '🚨 Critical - Immediate remediation required'
    }
    
    print(f"\nOverall Grade: {grade}")
    print(f"Assessment: {grade_meanings.get(grade, 'Unknown')}\n")
    
    print(f"Total Findings: {plan_data['summary']['total_findings']}")
    print(f"Total Remediation Effort: {plan_data.get('total_effort_hours', 0)} hours")
    print(f"Timeline Impact: {'2-4 weeks' if plan_data.get('total_effort_hours', 0) < 50 else '1-2+ months'}\n")
    
    print("Recommended Actions:")
    if plan_data['summary']['critical'] > 0:
        print(f"  1️⃣  Fix critical vulnerabilities ({plan_data['summary']['critical']} items) - THIS WEEK")
    if plan_data['summary']['high'] > 0:
        print(f"  2️⃣  Schedule high-severity patches ({plan_data['summary']['high']} items) - NEXT SPRINT")
    if plan_data['summary']['medium'] > 0:
        print(f"  3️⃣  Plan medium-risk updates ({plan_data['summary']['medium']} items) - SPRINT +1")
    
    print("\n" + "="*80)
    print("✅ Full Application Demo Complete!")
    print("="*80 + "\n")
    
    return True


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
