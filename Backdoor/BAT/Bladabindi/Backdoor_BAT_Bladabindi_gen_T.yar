
rule Backdoor_BAT_Bladabindi_gen_T{
	meta:
		description = "Backdoor:BAT/Bladabindi.gen!T,SIGNATURE_TYPE_PEHSTR,0c 00 0b 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {03 02 61 1f 17 59 45 01 00 00 00 04 00 00 00 16 } //01 00 
		$a_01_1 = {04 03 61 1f 43 59 45 01 00 00 00 04 00 00 00 1c } //0a 00 
		$a_01_2 = {20 7b 30 00 00 9d 06 1a 20 34 1d 00 00 9d 06 1b 20 97 1f 00 00 9d } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_BAT_Bladabindi_gen_T_2{
	meta:
		description = "Backdoor:BAT/Bladabindi.gen!T,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {d0 1b 00 00 06 26 1b 0a 2b d0 04 03 61 1f 4b 59 45 01 00 00 00 04 00 00 00 17 } //01 00 
		$a_01_1 = {05 04 61 1f 38 59 45 01 00 00 00 04 00 00 00 16 0a 2b bd } //01 00 
		$a_01_2 = {05 04 61 1f 39 59 45 01 00 00 00 02 00 00 00 2b ef 00 02 03 } //00 00 
	condition:
		any of ($a_*)
 
}