
rule TrojanSpy_AndroidOS_SmForw_C_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmForw.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 6a 73 68 79 6d 65 64 69 61 2e 6a 73 68 79 70 61 79 2e 70 6c 75 73 2e 41 70 70 50 6c 75 73 } //01 00 
		$a_00_1 = {6a 61 72 44 61 74 61 2e 6a 61 72 } //01 00 
		$a_00_2 = {41 75 74 6f 41 6e 73 5f 53 65 6e 64 } //01 00 
		$a_00_3 = {73 79 73 5f 73 65 6e 64 65 64 } //01 00 
		$a_00_4 = {61 6e 64 72 2f 75 70 6c 6f 61 64 6c 6f 67 } //00 00 
	condition:
		any of ($a_*)
 
}