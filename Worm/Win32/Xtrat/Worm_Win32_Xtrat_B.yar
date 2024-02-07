
rule Worm_Win32_Xtrat_B{
	meta:
		description = "Worm:Win32/Xtrat.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {75 00 70 00 64 00 61 00 74 00 65 00 73 00 65 00 72 00 76 00 65 00 72 00 6c 00 6f 00 63 00 61 00 6c 00 00 00 } //01 00 
		$a_01_1 = {64 00 6f 00 77 00 6e 00 65 00 78 00 65 00 63 00 } //01 00  downexec
		$a_01_2 = {58 00 74 00 72 00 65 00 6d 00 65 00 20 00 52 00 41 00 54 00 } //01 00  Xtreme RAT
		$a_01_3 = {55 6e 69 74 46 75 6e 63 6f 65 73 44 69 76 65 72 73 61 73 } //01 00  UnitFuncoesDiversas
		$a_01_4 = {55 6e 69 74 4b 65 79 6c 6f 67 67 65 72 } //00 00  UnitKeylogger
		$a_00_5 = {5d 04 00 } //00 2c 
	condition:
		any of ($a_*)
 
}