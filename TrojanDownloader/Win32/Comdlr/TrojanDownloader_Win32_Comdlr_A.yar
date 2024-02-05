
rule TrojanDownloader_Win32_Comdlr_A{
	meta:
		description = "TrojanDownloader:Win32/Comdlr.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 8b 55 e8 03 42 24 8b 55 e0 03 d2 03 c2 66 8b 00 66 89 45 de 66 83 45 de 03 8b 45 fc 8b 55 e8 03 42 1c 0f b7 55 de c1 e2 02 03 c2 89 45 d8 8b 45 d8 8b 00 03 45 fc 89 45 f4 eb 08 } //01 00 
		$a_03_1 = {6a 00 6a 00 6a 01 6a 00 6a 02 68 00 00 00 40 8b 45 f8 e8 90 01 04 50 e8 90 01 04 89 45 ec 6a 06 6a 01 6a 02 e8 90 01 04 89 45 f0 8b 45 d8 e8 90 01 04 50 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}