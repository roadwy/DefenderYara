
rule Worm_Win32_Xtrat_B_A{
	meta:
		description = "Worm:Win32/Xtrat.B!A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {58 00 54 00 52 00 45 00 4d 00 45 00 } //01 00  XTREME
		$a_01_1 = {58 74 72 65 6d 65 20 52 41 54 } //01 00  Xtreme RAT
		$a_01_2 = {55 6e 69 74 43 6f 6e 66 69 67 73 00 } //01 00  湕瑩潃普杩s
		$a_01_3 = {55 6e 69 74 43 72 79 70 74 53 74 72 69 6e 67 00 } //01 00  湕瑩牃灹却牴湩g
		$a_01_4 = {55 6e 69 74 4b 65 79 6c 6f 67 67 65 72 } //01 00  UnitKeylogger
		$a_01_5 = {45 64 69 74 53 76 72 00 } //00 00  摅瑩癓r
		$a_00_6 = {80 10 00 } //00 ed 
	condition:
		any of ($a_*)
 
}