
rule Backdoor_AndroidOS_HeHe_A_MTB{
	meta:
		description = "Backdoor:AndroidOS/HeHe.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {49 6e 63 6f 6d 65 43 61 6c 6c 41 6e 64 53 6d 73 52 65 63 65 69 76 65 72 } //01 00 
		$a_00_1 = {64 65 6c 65 74 65 20 73 6d 73 20 63 61 6c 6c } //01 00 
		$a_00_2 = {74 72 61 6e 73 66 65 72 43 61 6c 6c 49 6e 66 6f } //01 00 
		$a_00_3 = {6d 73 67 2e 61 70 6b } //01 00 
		$a_00_4 = {53 69 6c 65 6e 63 65 49 6e 73 74 61 6c 6c } //01 00 
		$a_00_5 = {69 6e 74 65 72 63 65 70 74 49 6e 66 6f } //00 00 
		$a_00_6 = {5d 04 00 00 09 } //8e 04 
	condition:
		any of ($a_*)
 
}