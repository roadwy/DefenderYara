
rule Backdoor_BAT_LimeRAT_A_bit{
	meta:
		description = "Backdoor:BAT/LimeRAT.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 02 00 "
		
	strings :
		$a_01_0 = {4c 69 6d 65 52 41 54 } //01 00 
		$a_01_1 = {00 46 69 6c 65 5f 44 65 63 00 } //01 00 
		$a_01_2 = {52 00 61 00 6e 00 73 00 2d 00 53 00 74 00 61 00 74 00 75 00 73 00 } //01 00 
		$a_01_3 = {00 53 70 6c 69 74 42 79 57 6f 72 64 00 } //01 00 
		$a_01_4 = {00 50 61 73 74 65 62 69 6e 00 } //01 00 
		$a_01_5 = {00 42 4f 54 00 } //01 00 
		$a_01_6 = {00 53 50 4c 00 } //00 00 
	condition:
		any of ($a_*)
 
}