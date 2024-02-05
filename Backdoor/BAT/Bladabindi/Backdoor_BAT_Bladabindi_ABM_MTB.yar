
rule Backdoor_BAT_Bladabindi_ABM_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.ABM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 03 00 "
		
	strings :
		$a_01_0 = {57 95 a2 3d 09 07 00 00 00 00 00 00 00 00 00 00 02 00 00 00 9b 00 00 00 18 00 00 00 70 00 00 00 34 01 00 00 86 01 00 00 } //01 00 
		$a_01_1 = {73 39 31 39 74 4f 57 76 38 57 } //01 00 
		$a_01_2 = {46 6c 75 73 68 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00 
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00 
		$a_01_4 = {45 6b 34 62 54 77 48 42 4c 70 } //00 00 
	condition:
		any of ($a_*)
 
}