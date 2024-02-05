
rule Adware_AndroidOS_MobiDash_V_MTB{
	meta:
		description = "Adware:AndroidOS/MobiDash.V!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 74 68 6f 72 61 70 70 73 2f 69 6e 63 68 65 73 74 6f 63 65 6e 74 69 6d 65 74 65 72 73 2f 50 72 6f 76 69 64 65 72 } //01 00 
		$a_01_1 = {44 65 78 43 6c 61 73 73 4c 6f 61 64 65 72 } //01 00 
		$a_01_2 = {69 6e 63 68 65 73 74 6f 63 65 6e 74 69 6d 65 74 65 72 73 2e 64 62 } //01 00 
		$a_01_3 = {4d 6f 62 69 6c 65 41 64 73 } //01 00 
		$a_01_4 = {4e 6f 74 69 66 69 63 61 74 69 6f 6e 4c 69 73 74 65 6e 65 72 } //01 00 
		$a_01_5 = {4f 6e 41 70 70 49 6e 73 74 61 6c 6c 41 64 4c 6f 61 64 65 64 4c 69 73 74 65 6e 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}