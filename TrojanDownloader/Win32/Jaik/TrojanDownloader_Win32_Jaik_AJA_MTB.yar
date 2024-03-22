
rule TrojanDownloader_Win32_Jaik_AJA_MTB{
	meta:
		description = "TrojanDownloader:Win32/Jaik.AJA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 45 dc 89 45 e0 89 45 e4 89 45 e8 89 45 ec 89 45 f0 89 45 f4 89 45 f8 89 45 fc a1 ec 7f cb 00 33 c5 89 45 fc 89 4d f8 c7 45 e0 0b 00 00 00 c6 45 e4 21 c6 45 e5 14 c6 45 e6 2f c6 45 e7 20 c6 45 e8 1a c6 45 e9 2b c6 45 ea 13 c6 45 eb e6 c6 45 ec 2f c6 45 ed 14 c6 45 ee 2f c6 45 ef 0c c6 45 f0 3b c6 45 f1 d1 33 c0 } //00 00 
	condition:
		any of ($a_*)
 
}