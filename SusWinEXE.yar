/* ===============================
   Rule: Suspicious Windows Executable
   Detects PE files with suspicious strings
   Author: Abdelhady
   =============================== */

rule Suspicious_PE_Sample
{
    meta:
        author = "Abdelhady"
        description = "Detects suspicious PE files with known bad strings"
        date = "2025-08-05"
        malware_family = "Generic"

    strings:
        $mz = { 4D 5A }                         // MZ header
        $s1 = "keylogger"
        $s2 = "reverse_shell"
        $s3 = "cmd.exe /c"

    condition:
        $mz at 0 and 1 of ($s1, $s2, $s3)
}
