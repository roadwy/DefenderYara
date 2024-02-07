
rule TrojanDownloader_Win32_Upatre_BW{
	meta:
		description = "TrojanDownloader:Win32/Upatre.BW,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 c0 b0 26 48 66 ab b0 74 40 66 ab 33 c0 66 ab } //01 00 
		$a_01_1 = {fc ad ab 33 c0 66 ad ab e2 f7 } //01 00 
		$a_01_2 = {3d 64 64 72 65 e0 f6 67 e3 c1 46 46 46 ad 2d 73 73 3a 20 } //01 00 
		$a_01_3 = {25 73 25 73 00 25 73 5c 25 73 00 6f 70 65 6e } //01 00 
		$a_01_4 = {00 74 65 78 74 2f 2a 00 } //01 00  琀硥⽴*
		$a_01_5 = {00 61 70 70 6c 69 63 61 74 69 6f 6e 2f 2a 00 } //00 00 
		$a_00_6 = {7e 15 00 00 } //7b f9 
	condition:
		any of ($a_*)
 
}