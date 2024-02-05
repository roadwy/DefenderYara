
rule Trojan_AndroidOS_TyStu_T_MTB{
	meta:
		description = "Trojan:AndroidOS/TyStu.T!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 61 6e 64 2f 73 6e 64 2f 4e 6f 74 69 66 69 65 72 } //01 00 
		$a_00_1 = {74 79 70 33 73 74 75 64 69 6f 73 } //01 00 
		$a_00_2 = {77 77 77 2e 70 69 78 65 6c 74 72 61 63 6b 36 36 2e 63 6f 6d 2f 6d 74 2f } //01 00 
		$a_00_3 = {41 64 64 69 74 69 6f 6e 61 6c 41 70 70 73 } //01 00 
		$a_00_4 = {26 6d 6f 62 69 6c 65 5f 6e 75 6d 62 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}