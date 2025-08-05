rule Encoded_PowerShell
{
    meta:
        author = "Abdelhady"
        category = "script"
        date = "2025-08-07"

    strings:
        $ps1 = "powershell.exe"
        $ps2 = "-enc"
        $ps3 = "-EncodedCommand"

    condition:
        $ps1 and ($ps2 or $ps3)
}
