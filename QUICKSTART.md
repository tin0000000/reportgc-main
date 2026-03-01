# 🚀 ReportGC - Quick Start Guide

## Prerequisites

- **Python 3.11+** (or Python 3.9+)
- **pip** (Python package manager)
- **Windows/Mac/Linux**

Check your Python version:
```bash
python --version
```

---

## 🔧 Installation (One-Time Setup)

### Step 1: Navigate to the Project Directory

```bash
cd c:\Users\mtavo\Downloads\reportgc-main\reportgc-main
```

Or if you cloned it elsewhere:
```bash
cd /path/to/reportgc-main
```

### Step 2: Create Virtual Environment (Recommended)

**Windows:**
```bash
python -m venv venv
.\venv\Scripts\Activate.ps1
```

**Mac/Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

This installs:
- `fastapi` - Web API framework
- `uvicorn` - ASGI server
- `python-pptx` - PowerPoint generation
- `pydantic` - Data validation
- `pytest` - Testing framework
- Plus others (see `requirements.txt`)

---

## ▶️ How to Run

### 🎯 **Option 1: Quick Local Test (EASIEST - No Server Needed)**

Run this to test everything locally with sample data:

```bash
python local_test.py
```

**What it does:**
```
✅ Creates sample vulnerabilities
✅ Processes through the security engine
✅ Classifies risks (Critical/High/Medium/Low)
✅ Generates PowerPoint report
✅ Shows executive summary
```

**Output:**
- Displays results in terminal
- Saves PPTX file to: `%TEMP%\reportgc_local\ReportGC-{timestamp}.pptx`
- Runtime: ~2 seconds

**Expected Output:**
```
================================================================================
                 🔒 ReportGC - Local Testing Suite
================================================================================

📋 TEST 1: Creating Sample Vulnerability Scan
✅ Created sample scan with 4 vulnerabilities

📊 TEST 2: Processing Through SecurityExplainPlan Engine
✅ Engine processed 4 findings successfully

   Grade: B
   Report ID: 202602-28-232735
   Total Findings: 4
   Total Effort: 36 hours

[... more output ...]

Report saved to: C:\Users\mtavo\AppData\Local\Temp\reportgc_local\ReportGC-20260228-232735.pptx
```

---

### 📊 **Option 2: Run Full Test Suite**

Verify all 41 tests pass:

```bash
python -m pytest tests/test_engine.py tests/test_pptx_generator.py -v
```

**Expected Result:**
```
============================= 41 passed in 0.45s =============================
✅ Core Engine Tests:        25/25 PASSING
✅ PPTX Generator Tests:     16/16 PASSING
✅ Total Test Suite:         41/41 PASSING (100%)
```

---

### 🎬 **Option 3: Run Demo Scripts**

#### Basic Demo
```bash
python demo.py
```

Shows:
- 6 sample vulnerabilities
- Risk classification
- Effort estimates
- Executive summary

#### Comprehensive Demo
```bash
python app_demo.py
```

Shows:
- 4-phase test suite
- Engine processing
- PPTX generation
- API endpoint simulation
- Detailed risk assessment

---

### 🌐 **Option 4: Launch REST API Server**

Start the API for programmatic access:

```bash
python api_local.py
```

**Output:**
```
80 ReportGC API Server - Local Testing
==============================================================================

📡 Server Starting...
   URL:  http://127.0.0.1:8000
   Docs: http://127.0.0.1:8000/docs
   ReDoc: http://127.0.0.1:8000/redoc

📝 Available Endpoints:
   GET  /              - Welcome message
   GET  /health        - Health check
   POST /api/validate  - Validate scan format
   POST /api/report    - Generate PPTX report
   POST /api/report/metadata - Get JSON metadata
```

#### Access the API:
- **Interactive Docs:** http://127.0.0.1:8000/docs
- **Health Check:** http://127.0.0.1:8000/health

#### Example: Generate a Report via API

Using `curl`:
```bash
curl -X POST http://127.0.0.1:8000/api/report/metadata \
  -H "Content-Type: application/json" \
  -d '{
    "Results": [{
      "Vulnerabilities": [{
        "VulnerabilityID": "CVE-2024-0001",
        "Title": "Test Vulnerability",
        "Severity": "CRITICAL",
        "CVSS": {"nvd": {"V3Score": 9.8}},
        "FixedVersion": "1.0.1",
        "PkgName": "test-package",
        "InstalledVersion": "1.0.0"
      }]
    }]
  }'
```

Using Python:
```python
import requests
import json

scan_data = {
    "Results": [{
        "Vulnerabilities": [{
            "VulnerabilityID": "CVE-2024-0001",
            "Title": "RCE Vulnerability",
            "Severity": "CRITICAL",
            "CVSS": {"nvd": {"V3Score": 9.8}},
            "FixedVersion": "1.0.1",
            "PkgName": "openssl",
            "InstalledVersion": "1.0.0"
        }]
    }]
}

# Get metadata as JSON
response = requests.post(
    "http://127.0.0.1:8000/api/report/metadata",
    json=scan_data
)
print(json.dumps(response.json(), indent=2))

# Download PPTX file
response = requests.post(
    "http://127.0.0.1:8000/api/report",
    json=scan_data
)
with open("report.pptx", "wb") as f:
    f.write(response.content)
```

---

## 📊 Understanding the Output

### Grade System (A-F)

| Grade | Meaning | Action Required |
|-------|---------|-----------------|
| **A** | ✅ Excellent | Maintain current practices |
| **B** | ⚠️ Good | Address critical findings |
| **C** | ⚠️ Concerning | Multiple high-risk issues |
| **D** | ❌ Poor | Significant security debt |
| **F** | 🚨 Critical | Immediate remediation required |

### Risk Classification

The system uses database query terms that executives understand:

| Risk Level | Database Equivalent | Timeline | CVSS Range |
|-----------|-------------------|----------|-----------|
| 🔴 **FULL_TABLE_SCAN** | Query killing database | **THIS WEEK** | ≥9.0 or CISA KEV |
| 🟠 **INDEX_RANGE_SCAN** | Suboptimal performance | **NEXT SPRINT** | 7.0-8.9 |
| 🟡 **NESTED_LOOP** | Inefficient join | **SPRINT +1** | 4.0-6.9 |
| 🟢 **SEQUENTIAL_READ** | Background operation | **QUARTERLY** | <4.0 |

### Effort Estimates

- **Critical Core Packages:** 24 hours (kernel, glibc, openssl)
- **No Fix Available:** 8 hours
- **CVSS ≥ 9.0:** 6 hours
- **Standard Patch:** 4 hours

---

## 📂 File Locations

### Generated Reports
```
Windows: C:\Users\{username}\AppData\Local\Temp\reportgc_local\
Report format: ReportGC-{YYYYMMDD-HHMMSS}.pptx
```

### Source Code
```
c:\Users\mtavo\Downloads\reportgc-main\reportgc-main\

Core Files:
├── engine.py              (Risk classification engine)
├── pptx_generator.py      (PowerPoint generation)
├── main.py                (Pipeline orchestrator)
└── report_generator.py    (HTML/PDF reports)

Running Locally:
├── local_test.py          (Complete test)
├── demo.py                (Basic demo)
├── app_demo.py            (Comprehensive demo)
└── api_local.py           (REST API server)

Tests:
└── tests/
    ├── test_engine.py     (25 tests)
    ├── test_pptx_generator.py (16 tests)
    └── conftest.py        (Shared fixtures)
```

---

## 🔍 Troubleshooting

### Problem: `ModuleNotFoundError: No module named 'X'`

**Solution:**
```bash
pip install -r requirements.txt
```

### Problem: Port 8000 already in use

**Solution:** Use different port
```bash
# Edit api_local.py line at bottom:
# Change: port=8000
# To:     port=8001
```

### Problem: Virtual environment not activating

**Windows:**
```bash
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
.\venv\Scripts\Activate.ps1
```

**Mac/Linux:**
```bash
source venv/bin/activate
```

### Problem: `WeasyPrint` missing system libraries (Windows)

**Solution:** Just use `local_test.py` - it doesn't require WeasyPrint
```bash
python local_test.py  # ✅ Works on Windows
```

---

## 📝 Quick Examples

### Example 1: Test with Your Own Scan Data

Create a file `my_scan.py`:

```python
from engine import SecurityExplainPlan

# Your Trivy or SARIF scan data
scan_data = {
    "Results": [{
        "Vulnerabilities": [
            {
                "VulnerabilityID": "CVE-2024-0001",
                "Title": "Your vulnerability",
                "Severity": "HIGH",
                "CVSS": {"nvd": {"V3Score": 7.5}},
                "FixedVersion": "2.0.0",
                "PkgName": "your-package",
                "InstalledVersion": "1.0.0"
            }
        ]
    }]
}

# Process through engine
engine = SecurityExplainPlan(scan_data)
result = engine.to_dict()

# Print results
print(f"Grade: {result['grade']}")
print(f"Findings: {result['summary']['total_findings']}")
print(f"Effort: {result.get('total_effort_hours', 0)} hours")
```

Run it:
```bash
python my_scan.py
```

### Example 2: Generate PPTX from Your Data

Create a file `generate_report.py`:

```python
from engine import SecurityExplainPlan
from pptx_generator import PPTXGenerator
from pathlib import Path

# Your scan data
scan_data = {"Results": [{ ... }]}  # Your vulnerability data

# Process
engine = SecurityExplainPlan(scan_data)
data = engine.to_dict()

# Generate PPTX
pptx_gen = PPTXGenerator()
output_path = Path.home() / "Desktop" / "SecurityReport.pptx"
pptx_gen.generate_pptx(data, str(output_path))

print(f"Report saved to: {output_path}")
```

Run it:
```bash
python generate_report.py
```

---

## ✅ Verification Checklist

After setup, verify everything works:

```bash
# 1. Check Python version
python --version
# Expected: Python 3.11.9 (or 3.9+)

# 2. Activate virtual environment
.\venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run quick test
python local_test.py
# Expected: "✅ All Tests Passed!"

# 5. Run test suite
python -m pytest tests/ -v
# Expected: "41 passed in 0.45s"

# 6. Try a demo
python app_demo.py
# Expected: Full demo output with grades and recommendations
```

---

## 📞 Support

### Common Questions

**Q: Can I use my own Trivy scan output?**
A: Yes! Export your Trivy scan as JSON and use it with the engine.

**Q: What format does the API expect?**
A: Trivy JSON (standard) or SARIF format from any SAST/container scanner.

**Q: How do I integrate this into my CI/CD pipeline?**
A: Use the REST API (`api_local.py`) or import the engine directly in Python.

**Q: Where are the PPTX reports saved?**
A: Check the script output or look in `%TEMP%/reportgc_local/` on Windows.

**Q: Can I customize the grading logic?**
A: Yes, edit the `risk_level` property in `engine.py` and the `grade` property in `SecurityExplainPlan` class.

---

## 🎯 Next Steps

1. **Run the local test:** `python local_test.py`
2. **Open the generated PPTX file** in PowerPoint
3. **Modify the sample data** to try different scenarios
4. **Run the full test suite** to verify everything
5. **Import the engine** into your own Python scripts

---

## 📚 File Reference

| File | Purpose | Run Command |
|------|---------|------------|
| `local_test.py` | Complete local test | `python local_test.py` |
| `demo.py` | Basic demo | `python demo.py` |
| `app_demo.py` | Comprehensive demo | `python app_demo.py` |
| `api_local.py` | REST API server | `python api_local.py` |
| Tests | Verify functionality | `pytest tests/ -v` |

---

**You're all set! Start with `python local_test.py` 🚀**
