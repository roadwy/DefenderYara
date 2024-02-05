
rule HackTool_BAT_MoDiRat{
	meta:
		description = "HackTool:BAT/MoDiRat,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 6f 44 69 20 52 41 54 } //01 00 
		$a_01_1 = {61 75 64 69 6f 66 72 6d 00 } //01 00 
		$a_01_2 = {4b 79 6c 6f 67 73 00 } //01 00 
		$a_01_3 = {64 65 6d 61 72 72 61 67 65 00 } //01 00 
		$a_01_4 = {77 65 62 63 61 6d 5f 4c 6f 61 64 } //01 00 
		$a_01_5 = {53 70 65 61 6b 46 6f 72 6d 5f 4c 6f 61 64 } //01 00 
		$a_01_6 = {4d 00 6f 00 44 00 69 00 20 00 52 00 41 00 54 00 } //00 00 
		$a_00_7 = {5d 04 00 } //00 dc 
	condition:
		any of ($a_*)
 
}