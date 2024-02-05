
rule Adware_AndroidOS_MobiDash_F_MTB{
	meta:
		description = "Adware:AndroidOS/MobiDash.F!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 66 69 72 65 73 74 72 65 61 6d 2f 74 69 74 61 6e 63 6f 6e 71 75 65 73 74 } //01 00 
		$a_01_1 = {2f 73 79 73 74 65 6d 2f 61 70 70 2f 53 75 70 65 72 75 73 65 72 2e 61 70 6b } //01 00 
		$a_01_2 = {6d 6f 62 69 6c 65 61 64 73 } //01 00 
		$a_01_3 = {49 6e 74 65 72 73 74 69 74 69 61 6c 41 64 } //01 00 
		$a_01_4 = {44 65 78 43 6c 61 73 73 4c 6f 61 64 65 72 } //01 00 
		$a_01_5 = {74 69 74 61 6e 63 6f 6e 71 75 65 73 74 2e 63 6f 6d } //00 00 
	condition:
		any of ($a_*)
 
}