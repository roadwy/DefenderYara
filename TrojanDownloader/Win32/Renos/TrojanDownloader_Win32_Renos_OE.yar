
rule TrojanDownloader_Win32_Renos_OE{
	meta:
		description = "TrojanDownloader:Win32/Renos.OE,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 14 11 80 e2 0f 32 c2 88 45 f1 33 c0 8a 45 f3 8b 55 fc 8a 04 02 24 f0 24 f0 8a 55 f1 02 c2 33 d2 8a 55 f3 8b 4d f4 88 04 11 } //01 00 
		$a_03_1 = {8b 44 c2 08 8b 55 90 01 01 8d 14 92 8b 4d 90 01 01 3b 44 d1 10 73 90 00 } //01 00 
		$a_03_2 = {ff 50 30 8b 55 f4 89 42 90 01 01 a1 90 01 04 50 8b 45 c8 50 8b 45 f4 ff 50 30 8b 55 f4 89 42 3c 90 00 } //01 00 
		$a_03_3 = {0f b7 40 06 48 85 c0 0f 82 90 01 04 40 89 45 ec c7 45 f0 00 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}