
rule Trojan_Win32_Downloader_TA_MTB{
	meta:
		description = "Trojan:Win32/Downloader.TA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {33 da d3 cb 33 c2 d3 c8 3b 5d f8 89 5d f0 8b 5d ec 75 05 3b 45 f4 74 af 8b 75 f0 8b f8 89 45 f4 eb a2 } //01 00 
		$a_01_1 = {68 74 74 70 3a 2f 2f 77 66 73 64 72 61 67 6f 6e 2e 72 75 2f 61 70 69 2f 73 65 74 53 74 61 74 73 2e 70 68 70 } //01 00 
		$a_01_2 = {68 74 74 70 3a 2f 2f 33 37 2e 30 2e 31 30 2e 32 31 34 2f 70 72 6f 78 69 65 73 2e 74 78 74 } //00 00 
	condition:
		any of ($a_*)
 
}