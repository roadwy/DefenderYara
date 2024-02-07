
rule PWS_Win32_OnLineGames_CG{
	meta:
		description = "PWS:Win32/OnLineGames.CG,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {44 69 76 78 44 65 63 6f 64 65 00 48 6f 6f 6b 6f 66 66 00 48 6f 6f 6b 6f 6e } //01 00 
		$a_00_1 = {00 77 6f 6f 6f 6c 2e 64 61 74 } //01 00  眀潯汯搮瑡
		$a_00_2 = {00 61 76 70 2e 65 78 65 } //01 00  愀灶攮數
		$a_03_3 = {6a 00 52 8d 90 01 04 00 00 68 14 01 00 00 50 57 ff 15 90 01 02 40 00 90 00 } //01 00 
		$a_03_4 = {68 b8 0b 00 00 f3 ab 66 90 01 04 ff 15 90 01 02 40 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}