
rule Backdoor_AndroidOS_Basdoor_B_MTB{
	meta:
		description = "Backdoor:AndroidOS/Basdoor.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {68 69 64 65 41 70 70 49 63 6f 6e } //01 00 
		$a_00_1 = {5f 73 65 6e 64 6c 61 72 67 65 73 6d 73 } //01 00 
		$a_00_2 = {49 20 48 61 76 65 20 41 63 63 65 73 73 20 3a 29 } //01 00 
		$a_00_3 = {40 72 6f 6f 74 44 72 44 65 76 3a } //01 00 
		$a_00_4 = {67 65 74 41 6c 6c 53 4d 53 } //01 00 
		$a_00_5 = {67 65 74 63 6f 6e 74 61 63 74 73 } //01 00 
		$a_00_6 = {62 6f 6d 62 } //00 00 
		$a_00_7 = {5d 04 00 00 0d } //10 05 
	condition:
		any of ($a_*)
 
}