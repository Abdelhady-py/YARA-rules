rule Ransomware_Generic
{
    meta:
        author = "Abdelhady"
        type = "ransomware"
        date = "2025-08-05"
        description = "Detects basic ransomware strings"

    strings:
        $msg = "All your files have been encrypted"
        $note = "contact us at"
        $bitcoin = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/

    condition:
        $msg and $note and $bitcoin
}
