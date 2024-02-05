
rule Adware_AndroidOS_MobiDash_Z_MTB{
	meta:
		description = "Adware:AndroidOS/MobiDash.Z!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 63 6f 6d 2f 6b 61 63 79 61 6e 6f 2f 6d 65 67 61 73 65 6e 61 } //01 00 
		$a_01_1 = {4c 63 6f 6d 2f 62 75 62 62 6c 69 6e 67 69 73 6f 2f 64 6d 76 63 68 69 6e 65 73 65 } //01 00 
		$a_01_2 = {64 6d 76 63 68 69 6e 65 73 65 2e 64 62 } //01 00 
		$a_01_3 = {44 65 78 43 6c 61 73 73 4c 6f 61 64 65 72 } //01 00 
		$a_01_4 = {73 65 6e 64 4e 6f 74 69 66 69 63 61 74 69 6f 6e } //00 00 
	condition:
		any of ($a_*)
 
}