
rule Worm_Win32_Xtrat_E{
	meta:
		description = "Worm:Win32/Xtrat.E,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 00 6d 00 53 00 65 00 63 00 75 00 72 00 65 00 52 00 41 00 54 00 } //01 00  ImSecureRAT
		$a_01_1 = {50 00 45 00 52 00 53 00 49 00 53 00 54 00 00 00 } //01 00 
		$a_01_2 = {64 00 6f 00 77 00 6e 00 65 00 78 00 65 00 63 00 } //01 00  downexec
		$a_01_3 = {55 6e 69 74 43 6f 6e 65 78 61 6f 00 } //01 00  湕瑩潃敮慸o
		$a_01_4 = {55 6e 69 74 46 75 6e 63 6f 65 73 44 69 76 65 72 73 61 73 } //01 00  UnitFuncoesDiversas
		$a_01_5 = {55 6e 69 74 4b 65 79 6c 6f 67 67 65 72 } //00 00  UnitKeylogger
		$a_00_6 = {5d 04 00 00 } //4b 44 
	condition:
		any of ($a_*)
 
}