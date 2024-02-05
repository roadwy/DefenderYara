
rule Backdoor_BAT_Bladabindi_gen_D{
	meta:
		description = "Backdoor:BAT/Bladabindi.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {4e 4a 53 65 72 76 65 72 } //01 00 
		$a_01_1 = {52 53 4d 44 65 63 72 79 70 74 } //01 00 
		$a_01_2 = {4e 00 4a 00 43 00 72 00 79 00 70 00 74 00 65 00 } //00 00 
		$a_00_3 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}