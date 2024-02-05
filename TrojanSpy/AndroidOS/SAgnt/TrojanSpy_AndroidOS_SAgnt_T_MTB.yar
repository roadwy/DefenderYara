
rule TrojanSpy_AndroidOS_SAgnt_T_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SAgnt.T!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 61 70 70 73 2f 6d 69 63 72 6f 73 6f 66 74 77 6f 72 64 61 70 6b } //01 00 
		$a_01_1 = {77 6f 72 64 72 65 73 75 6d 65 2e 68 65 72 6f 6b 75 61 70 70 2e 63 6f 6d } //01 00 
		$a_01_2 = {70 61 6b 63 65 72 74 2e 73 79 6e 63 73 65 72 76 69 63 65 2e 6f 72 67 } //01 00 
		$a_01_3 = {66 69 6c 65 5f 75 70 6c 6f 61 64 } //01 00 
		$a_01_4 = {65 6e 63 72 79 70 74 44 61 74 61 } //00 00 
	condition:
		any of ($a_*)
 
}