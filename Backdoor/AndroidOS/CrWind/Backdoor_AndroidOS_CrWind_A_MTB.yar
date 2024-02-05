
rule Backdoor_AndroidOS_CrWind_A_MTB{
	meta:
		description = "Backdoor:AndroidOS/CrWind.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 6f 73 74 49 6e 53 6d 73 } //01 00 
		$a_01_1 = {53 4d 53 5f 53 45 4e 54 } //01 00 
		$a_01_2 = {50 4f 53 54 5f 41 50 50 5f 4c 49 53 54 } //01 00 
		$a_01_3 = {67 65 74 53 65 6e 64 4e 75 6d 62 65 72 } //01 00 
		$a_01_4 = {75 6e 49 6e 73 74 61 6c 6c 41 70 70 } //01 00 
		$a_00_5 = {74 74 70 3a 2f 2f 63 72 75 73 65 77 69 6e 64 2e 6e 65 74 2f 66 6c 61 73 68 } //01 00 
		$a_00_6 = {4c 63 6f 6d 2f 66 6c 61 73 68 70 2f 46 6c 61 73 68 41 70 70 6c 69 63 61 74 69 6f 6e } //00 00 
	condition:
		any of ($a_*)
 
}