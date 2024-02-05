
rule Trojan_Win32_Downloader_CE_MTB{
	meta:
		description = "Trojan:Win32/Downloader.CE!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 44 25 00 8d ad 04 00 00 00 d2 d6 0f b6 16 66 f7 c2 7f 2b 81 c6 01 00 00 00 f7 c3 9d 10 65 25 32 d3 f6 d2 f8 80 f2 f5 e9 } //01 00 
		$a_01_1 = {23 d1 66 8b cc 0f 9d c1 66 f7 d1 89 55 04 0f bf cc e9 } //00 00 
	condition:
		any of ($a_*)
 
}