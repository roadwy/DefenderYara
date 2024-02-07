
rule Trojan_Win32_Downloader_RPE_MTB{
	meta:
		description = "Trojan:Win32/Downloader.RPE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 00 61 00 63 00 6b 00 65 00 72 00 } //01 00  Hacker
		$a_01_1 = {70 00 61 00 73 00 74 00 65 00 62 00 69 00 6e 00 2e 00 63 00 6f 00 6d 00 } //01 00  pastebin.com
		$a_01_2 = {45 00 78 00 70 00 6c 00 6f 00 69 00 74 00 } //01 00  Exploit
		$a_01_3 = {57 65 62 43 6c 69 65 6e 74 } //01 00  WebClient
		$a_01_4 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //00 00  DownloadString
	condition:
		any of ($a_*)
 
}