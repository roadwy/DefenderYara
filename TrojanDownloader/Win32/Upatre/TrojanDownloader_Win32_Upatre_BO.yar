
rule TrojanDownloader_Win32_Upatre_BO{
	meta:
		description = "TrojanDownloader:Win32/Upatre.BO,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 c0 b0 26 48 66 ab b0 74 40 66 ab 33 c0 66 ab } //01 00 
		$a_01_1 = {25 73 25 73 00 25 73 5c 25 73 00 6f 70 65 6e } //01 00 
		$a_01_2 = {00 74 65 78 74 2f 2a 00 } //01 00 
		$a_01_3 = {00 61 70 70 6c 69 63 61 74 69 6f 6e 2f 2a 00 } //01 00 
		$a_03_4 = {48 ab b0 52 66 ab 90 09 07 00 90 03 08 07 90 01 02 b8 54 00 45 00 68 55 00 45 00 58 48 90 00 } //01 00 
		$a_01_5 = {66 b8 34 00 66 ab b0 31 66 ab b0 2f 66 ab 8b c1 04 30 b4 00 66 ab b0 2f 66 ab ff 75 } //00 00 
		$a_00_6 = {7e 15 00 } //00 60 
	condition:
		any of ($a_*)
 
}