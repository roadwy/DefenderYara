
rule PUA_AndroidOS_Btapk_A_MTB{
	meta:
		description = "PUA:AndroidOS/Btapk.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 72 65 62 6f 6f 74 53 63 72 69 70 74 2e 70 7a } //01 00 
		$a_00_1 = {63 68 61 63 6b 43 6f 6d 6d 61 6e 64 } //01 00 
		$a_00_2 = {75 70 6c 6f 61 64 2e 61 73 70 78 } //01 00 
		$a_00_3 = {63 6f 6d 6d 61 6e 64 2e 74 78 74 } //01 00 
		$a_00_4 = {2f 67 67 65 78 65 53 74 61 72 74 41 70 6b 2e 74 78 74 } //01 00 
		$a_00_5 = {4c 69 61 6e 5a 68 6f 6e 67 44 61 69 44 61 43 61 6c 6c 2e 74 78 74 } //00 00 
	condition:
		any of ($a_*)
 
}