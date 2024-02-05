
rule TrojanDownloader_Win32_Beshades_A{
	meta:
		description = "TrojanDownloader:Win32/Beshades.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {b8 25 49 92 24 f7 e1 8b c1 2b c2 d1 e8 03 c2 c1 e8 04 8d 14 c5 00 00 00 00 2b d0 03 d2 03 d2 b8 90 a1 41 00 } //01 00 
		$a_01_1 = {68 b0 a1 41 00 ff 15 8c f0 41 00 6a 00 68 00 00 00 80 6a 00 6a 00 8b f8 55 57 89 7c 24 30 ff 15 90 f0 41 00 6a 01 8b d8 ff 15 14 a0 41 00 85 ff 74 c6 85 db 74 c2 6a 00 } //00 00 
	condition:
		any of ($a_*)
 
}