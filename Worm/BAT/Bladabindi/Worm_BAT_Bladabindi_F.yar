
rule Worm_BAT_Bladabindi_F{
	meta:
		description = "Worm:BAT/Bladabindi.F,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {02 7b 23 00 00 04 2d 24 02 02 25 fe 07 4d 00 00 06 73 34 00 00 0a 17 73 35 00 00 0a 7d 23 00 00 04 02 7b 23 00 00 04 6f c0 00 00 0a } //01 00 
		$a_01_1 = {1f 14 3c 25 01 00 00 02 07 08 02 08 28 cf 00 00 0a 6f 4f 00 00 06 6f 4e 00 00 06 26 06 7b 27 00 00 04 08 } //01 00 
		$a_01_2 = {03 6f c4 00 00 0a 04 73 20 00 00 0a 6f a8 00 00 0a 72 7d 08 00 70 28 3b 00 00 0a 28 a7 00 00 0a de 0e } //00 00 
		$a_00_3 = {87 } //10 00 
	condition:
		any of ($a_*)
 
}