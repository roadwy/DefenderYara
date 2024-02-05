
rule Trojan_Win32_Downloader_BZ_MTB{
	meta:
		description = "Trojan:Win32/Downloader.BZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 04 4b 88 04 39 83 c1 01 83 d2 00 33 c0 3b d0 7c ee 7f 04 3b ce 72 e8 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 4d 75 74 65 78 57 } //01 00 
		$a_01_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //01 00 
		$a_01_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //00 00 
	condition:
		any of ($a_*)
 
}