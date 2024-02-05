
rule TrojanDownloader_Win32_Vundo_F{
	meta:
		description = "TrojanDownloader:Win32/Vundo.F,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8d 1d 5c a0 00 10 03 03 ff e0 } //01 00 
		$a_03_1 = {00 10 8b 48 28 85 c9 74 14 a1 90 01 02 00 10 6a 00 03 c8 6a 90 01 01 50 89 0d 90 01 02 00 10 ff d1 c3 90 00 } //01 00 
		$a_03_2 = {83 ec 20 e8 90 01 01 e4 ff ff ff 15 90 01 01 90 90 00 10 68 d2 04 00 00 50 8d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}