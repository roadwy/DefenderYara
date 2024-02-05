
rule Worm_BAT_Bladabindi_gen_D{
	meta:
		description = "Worm:BAT/Bladabindi.gen!D,SIGNATURE_TYPE_PEHSTR,0f 00 0d 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {2d 07 72 c4 01 00 70 2b 05 } //01 00 
		$a_01_1 = {72 e4 01 00 70 } //01 00 
		$a_01_2 = {72 be 01 00 70 } //01 00 
		$a_01_3 = {72 b6 01 00 70 } //01 00 
		$a_01_4 = {72 7c 02 00 70 } //0a 00 
		$a_01_5 = {20 e9 01 00 00 20 8b 01 00 00 28 10 00 00 06 25 14 fe 06 03 00 00 06 73 07 00 00 0a 20 ea 03 00 00 20 f1 03 00 00 16 2c 2a 26 26 } //00 00 
	condition:
		any of ($a_*)
 
}