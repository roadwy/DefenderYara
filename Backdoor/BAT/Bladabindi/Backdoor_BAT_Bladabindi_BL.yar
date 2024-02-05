
rule Backdoor_BAT_Bladabindi_BL{
	meta:
		description = "Backdoor:BAT/Bladabindi.BL,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 05 00 "
		
	strings :
		$a_01_0 = {5b 00 65 00 6e 00 64 00 6f 00 66 00 5d 00 } //05 00 
		$a_01_1 = {7c 00 27 00 7c 00 27 00 7c 00 } //01 00 
		$a_01_2 = {5b 00 4d 00 65 00 5d 00 } //01 00 
		$a_01_3 = {42 53 00 42 00 44 45 42 00 } //01 00 
		$a_01_4 = {44 45 42 00 73 00 45 4e 42 00 } //01 00 
		$a_01_5 = {52 43 00 53 42 00 } //00 00 
		$a_00_6 = {5d 04 00 00 15 90 } //03 80 
	condition:
		any of ($a_*)
 
}