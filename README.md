# 🔍 YARA Rules Collection

A curated set of YARA rules for detecting suspicious files, malware behaviors, encoded PowerShell scripts, and Command & Control (C2) indicators.



---

## 🛡️ Rules Overview

### ✅ `SusWinEXE.yar`
Detects common malware patterns including:
- Suspicious PE file structures
- Ransomware signatures (ransom notes, Bitcoin addresses)

### 🌐 `C2url.yar`
Detects hardcoded or suspicious Command & Control (C2) URLs such as:
- `gate.php`
- `/panel/connect` endpoints

### ⚙️ `powershell.yar`
Looks for abuse of scripting tools like PowerShell, especially:
- Encoded PowerShell commands
- Obfuscated script execution

---

## 🧪 How to Use



```bash
yara -r rules/malware.yar /path/to/samples
