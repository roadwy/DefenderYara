
rule TrojanSpy_AndroidOS_FakeApp_T_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/FakeApp.T!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 6c 70 2f 73 6d 73 72 65 63 6f 72 64 73 2f 4d 6f 62 69 6c 65 4d 65 73 49 6e 66 6f } //01 00 
		$a_00_1 = {67 65 74 50 68 6f 6e 65 4d 65 73 73 61 67 65 } //01 00 
		$a_00_2 = {67 65 74 41 64 64 72 65 73 73 } //01 00 
		$a_00_3 = {6a 73 6d 65 74 68 6f 64 5f 67 65 74 73 6d 73 69 6e 66 6f } //01 00 
		$a_00_4 = {6a 73 6d 65 74 68 6f 64 5f 61 6c 6c 43 6f 6e 74 61 63 74 73 } //01 00 
		$a_00_5 = {44 65 63 6f 6d 70 69 6c 65 20 49 73 20 41 20 53 74 75 70 69 64 20 42 65 68 61 76 69 6f 72 } //00 00 
	condition:
		any of ($a_*)
 
}