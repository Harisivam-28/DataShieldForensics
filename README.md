# DataShield Forensics (Java 17 Project)

**Integrated Secure Data Erasure & Advanced Digital Forensics Engine**

DataShield Forensics is an enterprise digital forensics and NIST/DoD-compliant data sanitization platform ported to Java 17. It integrates evidence acquisition, multi-format signature carving, fragment reconstruction, physical storage drive analysis, and cryptographic audit chaining with zero external dependencies required to compile or run.

---

## Architecture & Features

### 1. Evidence-Aware Intelligent Data Lifecycle Engine (`org.datashield.core`)
* Enforces read-only locks on forensic evidence.
* **Pre-Erasure Safety Guard**: Prevents accidental data sanitization before evidence acquisition has occurred.

### 2. Cryptographic Audit Chain (`org.datashield.audit`)
* Tamper-evident ledger using SHA-256 hash chaining:
  $$\text{hash}_n = \text{SHA-256}(\text{id} \parallel \text{timestamp} \parallel \text{user} \parallel \text{caseId} \parallel \text{action} \parallel \text{details} \parallel \text{hash}_{n-1})$$
* Fast audit chain validation detecting any insertion, deletion, or record tampering.

### 3. Signature Carving & File Recovery Engine (`org.datashield.recovery`)
* Multi-format binary scanner supporting:
  * **JPEG Images** (`FF D8 FF` ... `FF D9`)
  * **PNG Images** (`89 50 4E 47` ... `49 45 4E 44`)
  * **PDF Documents** (`%PDF` ... `%%EOF`)
  * **ZIP Archives / Office DOCX/XLSX** (`50 4B 03 04` ... `50 4B 05 06`)
  * **MP4 Video** (`ftyp` ... `moov`)
  * **MP3 Audio** (`ID3`)
  * **Plaintext logs**
* **Explainable Confidence Scoring**: Evaluates headers, footers, entropy bounds, and fragment continuity.
* **Destination Separation Rule**: Ensures recovered files can never be written back to the source evidence device.

### 4. Certified Data Sanitization Engine (`org.datashield.erasure`)
* **DoD 5220.22-M (3-Pass Overwrite)**: Zero-fill, Ones-fill, Random pattern.
* **NIST SP 800-88 Rev 1 Purge**: ATA/NVMe Sanitize / Block Erase.
* **Gutmann 35-Pass Algorithm**: High-security magnetic media wiping.
* **Cryptographic Sanitization Certificates**: Audit certificate with pre/post-erasure SHA-256 hashes.

### 5. Hardware Device Detection (`org.datashield.device`)
* Real physical storage hardware detection via OS commands (`diskutil` on macOS, `lsblk` on Linux).
* Automatic safety identification to protect internal system disks.

### 6. Full REST API & Web UI Server (`org.datashield.server`)
* Zero-dependency HTTP server built using Java 17 `com.sun.net.httpserver`.
* Serves the complete REST API (Cases, Evidence, Recovery, Sanitization, Auditing, Verification).
* Serves the static production Single Page Application (SPA) frontend with client-side routing fallback.

---

## Directory Structure

```text
.
├── pom.xml                               # Maven project definition (Java 17)
├── build.sh                              # Standalone compilation and packaging script
├── run.sh                                # Execution script
├── test.sh                               # Test suite runner
├── src/
│   ├── main/java/org/datashield/
│   │   ├── DataShieldApplication.java    # Application entry point
│   │   ├── config/                       # Configuration constants
│   │   ├── model/                        # Domain models (Case, Evidence, Device, etc.)
│   │   ├── database/                     # Thread-safe embedded database store
│   │   ├── audit/                        # Cryptographic audit chain engine
│   │   ├── evidence/                     # Evidence acquisition & SHA-256 hashing
│   │   ├── core/                         # Lifecycle engine & pre-erasure guard
│   │   ├── device/                       # Real hardware drive detection
│   │   ├── recovery/                     # Signature carving & recovery engines
│   │   ├── erasure/                      # Sanitization methods & file shredder
│   │   ├── integrity/                    # System-wide forensic integrity verifier
│   │   ├── reports/                      # PDF & JSON report generator
│   │   ├── server/                       # REST API & static web UI HTTP server
│   │   └── util/                         # Zero-dependency JSON & SHA-256 utilities
│   └── test/java/org/datashield/
│       └── DataShieldTestSuite.java      # Comprehensive automated test suite
├── sample_data/                          # Forensic disk images & test sandbox
│   ├── sample_drive.img                  # 2 MB sample forensic disk image
│   └── sandbox/                          # Safe directory for file sanitization tests
└── frontend/dist/                        # Built SPA frontend assets
```

---

## Quick Start

### 1. Build the Project
```bash
./build.sh
```
Or with Maven:
```bash
mvn clean package
```

### 2. Run the Test Suite
```bash
./test.sh
```
Or directly:
```bash
java -jar target/datashield-forensics.jar --test
```

### 3. Start the Server
```bash
./run.sh
```
Or with custom port:
```bash
java -jar target/datashield-forensics.jar --port 5001
```

Once started:
* **Web UI Dashboard**: `http://localhost:5001/`
* **Health Check**: `http://localhost:5001/health`
* **System Status API**: `http://localhost:5001/api/status`
* **Cases API**: `http://localhost:5001/api/cases`
* **Audit Chain Verification**: `http://localhost:5001/api/audit/verify`

---

## REST API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Service health status |
| `GET` | `/api/status` | System metrics, evidence count, and lifecycle status |
| `GET` | `/api/cases` | Retrieve all investigation cases |
| `GET` | `/api/cases/{id}` | Detailed case dossier (evidence, recovered files, lifecycle) |
| `POST`| `/api/cases` | Register a new forensic investigation case |
| `GET` | `/api/evidence` | Evidence registry (supports `?caseId=...`) |
| `POST`| `/api/evidence` | Register forensic disk image and compute SHA-256 |
| `POST`| `/api/evidence/{id}/verify` | Verify evidence bitstream integrity |
| `GET` | `/api/devices` | Real physical storage device inventory |
| `GET` | `/api/devices/detect` | Execute live OS hardware scan |
| `GET` | `/api/recovery/signatures` | Supported file format signature database |
| `GET` | `/api/recovery/files` | Recovered files list (supports `?caseId=...`) |
| `POST`| `/api/recovery/carve` | Run multi-format signature carving on evidence |
| `POST`| `/api/recovery/validate-destination` | Enforce source-destination separation rule |
| `POST`| `/api/recovery/restore` | Restore recovered file to validated path |
| `POST`| `/api/recovery/reconstruct` | Multi-fragment reconstruction |
| `GET` | `/api/erasure/methods` | List standard sanitization standards (DoD, NIST, Gutmann) |
| `GET` | `/api/erasure/pre-check` | Pre-erasure safety guard evaluation |
| `POST`| `/api/erasure/drive` | Execute certified drive erasure & issue certificate |
| `GET` | `/api/sandbox/files` | List sandbox files available for shredding |
| `POST`| `/api/erasure/files` | Execute 3-pass file shredder on selected files |
| `GET` | `/api/verification` | System-wide integrity verification center |
| `GET` | `/api/audit` | Cryptographic audit trail logs |
| `GET` | `/api/audit/verify` | Verify SHA-256 chain of custody integrity |
| `GET` | `/api/reports` | List generated compliance reports |
| `POST`| `/api/reports/generate` | Generate forensic recovery / sanitization report |
| `GET` | `/api/reports/{id}/pdf` | Download official forensic PDF report |

