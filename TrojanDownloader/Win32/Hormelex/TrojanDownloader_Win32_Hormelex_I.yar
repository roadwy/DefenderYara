
rule TrojanDownloader_Win32_Hormelex_I{
	meta:
		description = "TrojanDownloader:Win32/Hormelex.I,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {64 89 20 33 c9 b2 01 a1 90 01 04 e8 90 01 04 8b d8 33 c0 55 68 90 01 04 64 ff 30 64 89 20 ba 90 01 04 8b c3 8b 08 ff 51 30 8d 45 fc b9 90 01 04 8b 15 90 00 } //01 00 
		$a_03_1 = {63 68 61 6d 31 30 31 30 90 02 20 2e 7a 69 70 90 00 } //01 00 
		$a_01_2 = {39 41 42 37 36 35 38 44 41 39 35 31 38 43 34 34 46 44 32 33 31 33 33 33 44 31 37 36 } //00 00 
	condition:
		any of ($a_*)
 
}