

rule C2_HTTP_Request
{
    meta:
        author = "Abdelhady"
        description = "Detects hardcoded C2 URLs in malware"
        category = "Network"
        date = "2025-08-05"

    strings:
        $url1 = /http:\/\/[a-z0-9\.-]+\/gate\.php/
        $url2 = /https:\/\/[a-z0-9\.-]+\/panel\/connect/

    condition:
        any of them
}
