
rule PUA_AndroidOS_MobiDash_A_MTB{
	meta:
		description = "PUA:AndroidOS/MobiDash.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 74 61 72 74 41 70 70 41 64 } //01 00 
		$a_01_1 = {41 75 64 69 6f 36 32 38 39 39 39 5f 50 6c 61 79 6c 69 73 74 4d 61 6e 61 67 65 72 } //01 00 
		$a_01_2 = {46 69 6c 65 44 6f 77 6e 6c 6f 61 64 65 72 } //01 00 
		$a_01_3 = {67 6f 6c 64 6d 65 6c 74 69 6e 67 63 61 6c 63 69 2e 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}