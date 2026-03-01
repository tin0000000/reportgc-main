#!/usr/bin/env python3
"""
ReportGC - Local Testing Script
Run this to test the full application locally without needing an API server
"""

import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent))

from engine import SecurityExplainPlan
from pptx_generator import PPTXGenerator


def create_sample_scan():
    """Create realistic sample vulnerability data for testing"""
    return {
        "Results": [
            {
                "Target": "myapp:latest",
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
                        "Title": "SQL Injection in Django ORM",
                        "Severity": "HIGH",
                        "CVSS": {"nvd": {"V3Score": 8.1}},
                        "FixedVersion": "3.2.23",
                        "PkgName": "django",
                        "InstalledVersion": "3.2.0",
                        "Description": "SQL injection vulnerability in ORM",
                        "CisaKnownExploited": False
                    },
                    {
                        "VulnerabilityID": "CVE-2024-0003",
                        "Title": "XSS in React",
                        "Severity": "MEDIUM",
                        "CVSS": {"nvd": {"V3Score": 5.3}},
                        "FixedVersion": "17.0.2",
                        "PkgName": "react",
                        "InstalledVersion": "17.0.0",
                        "Description": "Cross-site scripting vulnerability",
                        "CisaKnownExploited": False
                    },
                    {
                        "VulnerabilityID": "CVE-2024-0004",
                        "Title": "Information Disclosure in Flask",
                        "Severity": "LOW",
                        "CVSS": {"nvd": {"V3Score": 2.7}},
                        "FixedVersion": "2.0.3",
                        "PkgName": "flask",
                        "InstalledVersion": "2.0.0",
                        "Description": "Debug mode leaks sensitive information",
                        "CisaKnownExploited": False
                    },
                ]
            }
        ]
    }


def print_section(title, color=None):
    """Print a formatted section title"""
    colors = {
        "green": "\033[92m",
        "yellow": "\033[93m",
        "red": "\033[91m",
        "blue": "\033[94m",
        "end": "\033[0m"
    }
    color_code = colors.get(color, "")
    end_code = colors["end"] if color else ""
    
    print(f"\n{color_code}{'='*80}{end_code}")
    print(f"{color_code}{title:^80}{end_code}")
    print(f"{color_code}{'='*80}{end_code}\n")


def main():
    print_section("🔒 ReportGC - Local Testing Suite", "blue")
    
    # TEST 1: Data Validation
    print("📋 TEST 1: Creating Sample Vulnerability Scan")
    print("-" * 80)
    
    scan_data = create_sample_scan()
    num_vulns = len(scan_data['Results'][0]['Vulnerabilities'])
    print(f"✅ Created sample scan with {num_vulns} vulnerabilities\n")
    
    # TEST 2: Engine Processing
    print("📊 TEST 2: Processing Through SecurityExplainPlan Engine")
    print("-" * 80)
    
    try:
        engine = SecurityExplainPlan(scan_data)
        plan_data = engine.to_dict()
        print(f"✅ Engine processed {len(engine.findings)} findings successfully\n")
        
        print(f"   Grade: {plan_data['grade']}")
        print(f"   Report ID: {plan_data['report_id']}")
        print(f"   Generated: {plan_data['generated_at']}")
        print(f"   Total Findings: {plan_data['summary']['total_findings']}")
        print(f"   Total Effort: {plan_data.get('total_effort_hours', 0)} hours\n")
        
    except Exception as e:
        print(f"❌ Engine processing failed: {e}")
        return False
    
    # TEST 3: Risk Classification
    print("\n📊 TEST 3: Risk Classification Results")
    print("-" * 80)
    
    try:
        ep = plan_data['execution_plan']
        
        print(f"\n🔴 CRITICAL (FULL_TABLE_SCAN): {ep['full_table_scans']['count']} findings")
        if ep['full_table_scans']['items']:
            for item in ep['full_table_scans']['items']:
                print(f"   • {item['id']}: {item['title']}")
                print(f"     Package: {item['pkg_name']} {item['installed_version']}")
                print(f"     Effort: {item['fix_effort_hours']}h")
                print(f"     CVSS: {item['cvss_score']}")
        
        print(f"\n🟠 HIGH (INDEX_RANGE_SCAN): {ep['index_scans']['count']} findings")
        if ep['index_scans']['items']:
            for item in ep['index_scans']['items']:
                print(f"   • {item['id']}: {item['title']}")
                print(f"     Effort: {item['fix_effort_hours']}h")
        
        print(f"\n🟡 MEDIUM (NESTED_LOOP): {ep['nested_loops']['count']} findings")
        if ep['nested_loops']['items']:
            for item in ep['nested_loops']['items']:
                print(f"   • {item['id']}: {item['title']}")
        
        print(f"\n🟢 LOW (SEQUENTIAL_READ): {ep['low_priority']['count']} findings")
        if ep['low_priority']['items']:
            for item in ep['low_priority']['items']:
                print(f"   • {item['id']}: {item['title']}")
        
    except Exception as e:
        print(f"❌ Risk classification failed: {e}")
        return False
    
    # TEST 4: PPTX Generation
    print("\n🎨 TEST 4: Generating PowerPoint Presentation")
    print("-" * 80)
    
    try:
        pptx_gen = PPTXGenerator()
        output_dir = Path.home() / "AppData" / "Local" / "Temp" / "reportgc_local"
        output_dir.mkdir(parents=True, exist_ok=True)
        
        pptx_path = output_dir / f"ReportGC-{plan_data['report_id']}.pptx"
        pptx_gen.generate_pptx(plan_data, str(pptx_path))
        
        file_size_mb = pptx_path.stat().st_size / (1024 * 1024)
        print(f"✅ PowerPoint presentation generated\n")
        print(f"   File: {pptx_path.name}")
        print(f"   Path: {pptx_path}")
        print(f"   Size: {file_size_mb:.2f} MB\n")
        
    except Exception as e:
        print(f"❌ PPTX generation failed: {e}")
        return False
    
    # TEST 5: Summary Report
    print("\n📈 TEST 5: Executive Summary")
    print("-" * 80)
    
    grade = plan_data['grade']
    grade_meanings = {
        'A': '✅ Excellent - Strong security posture',
        'B': '⚠️  Good - Address critical findings',
        'C': '⚠️  Concerning - Multiple high-risk issues',
        'D': '❌ Poor - Significant security debt',
        'F': '🚨 Critical - Immediate remediation required'
    }
    
    print(f"\n📊 Overall Grade: {grade}")
    print(f"   {grade_meanings.get(grade, 'Unknown')}\n")
    
    print(f"📋 Findings Summary:")
    print(f"   Total: {plan_data['summary']['total_findings']}")
    print(f"   Critical: {plan_data['summary']['critical']}")
    print(f"   High: {plan_data['summary']['high']}")
    print(f"   Medium: {plan_data['summary']['medium']}")
    print(f"   Low: {plan_data['summary']['low']}")
    print(f"   CISA KEV: {plan_data['summary']['cisa_kev_count']}\n")
    
    effort = plan_data.get('total_effort_hours', 0)
    print(f"⏱️  Remediation Timeline:")
    print(f"   Total Effort: {effort} hours")
    if effort > 0:
        timeline = "1-2+ weeks" if effort < 20 else "2-4 weeks" if effort < 50 else "1-2+ months"
        print(f"   Estimated Timeline: {timeline}")
    
    print(f"\n✅ Recommended Actions:")
    if plan_data['summary']['critical'] > 0:
        print(f"   1. Fix {plan_data['summary']['critical']} critical vulnerabilities - THIS WEEK")
    if plan_data['summary']['high'] > 0:
        print(f"   2. Schedule {plan_data['summary']['high']} high-severity patches - NEXT SPRINT")
    if plan_data['summary']['medium'] > 0:
        print(f"   3. Plan {plan_data['summary']['medium']} medium-risk updates - SPRINT +1")
    
    # Final Summary
    print_section("✅ All Tests Passed!", "green")
    print(f"Report saved to: {pptx_path}")
    print(f"\nYou can now:")
    print(f"  1. Open the PPTX file to view the executive presentation")
    print(f"  2. Share the grade and findings with your team")
    print(f"  3. Use this data to prioritize remediation efforts")
    print(f"  4. Track progress over time as you fix vulnerabilities\n")
    
    return True


if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n❌ Test interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Unexpected error: {e}")
        sys.exit(1)
