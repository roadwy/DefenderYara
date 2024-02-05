
rule Trojan_Win32_Downloader_DP_MTB{
	meta:
		description = "Trojan:Win32/Downloader.DP!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {d0 c2 f8 80 c2 c2 f6 da 32 da 89 04 14 81 ee 04 00 00 00 02 d2 8b 16 3b e6 33 d3 c1 ca 03 f7 d2 d1 ca f6 c4 68 3c c2 f8 81 f2 e8 06 0b 15 66 f7 c2 2a 34 33 da f9 f5 03 ea e9 } //01 00 
		$a_01_1 = {81 ee 04 00 00 00 2b c1 8b 06 3b ea 33 c3 05 c4 49 c6 62 f7 d0 e9 } //00 00 
	condition:
		any of ($a_*)
 
}