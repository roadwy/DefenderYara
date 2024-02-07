
rule Worm_Win32_Xtrat_B_C{
	meta:
		description = "Worm:Win32/Xtrat.B!C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {58 00 74 00 72 00 65 00 6d 00 65 00 20 00 52 00 41 00 54 00 00 00 } //01 00 
		$a_01_1 = {50 00 45 00 52 00 53 00 49 00 53 00 54 00 00 00 } //01 00 
		$a_01_2 = {58 74 72 65 6d 65 20 52 41 54 20 55 6e 69 63 6f 64 65 5c 53 65 72 76 69 64 6f 72 5c } //01 00  Xtreme RAT Unicode\Servidor\
		$a_01_3 = {55 6e 69 74 43 6f 6e 65 78 61 6f 00 } //00 00  湕瑩潃敮慸o
		$a_00_4 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}