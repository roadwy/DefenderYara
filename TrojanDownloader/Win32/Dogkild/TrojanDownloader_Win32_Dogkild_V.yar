
rule TrojanDownloader_Win32_Dogkild_V{
	meta:
		description = "TrojanDownloader:Win32/Dogkild.V,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 19 56 8b f0 c1 ee 19 c1 e0 07 0b f0 0f be c1 8a 4a 01 33 c6 42 84 c9 75 e9 } //02 00 
		$a_03_1 = {6a 01 ff 55 f0 68 29 1c a8 58 6a 02 e8 90 01 04 89 45 ec 6a 00 6a 00 6a 10 ff 75 f8 ff 55 ec 90 00 } //01 00 
		$a_01_2 = {e9 03 00 00 00 ef 90 90 03 c1 0f b6 c2 8b d0 0f c0 d4 92 69 d0 ae d0 c5 dd } //00 00 
	condition:
		any of ($a_*)
 
}