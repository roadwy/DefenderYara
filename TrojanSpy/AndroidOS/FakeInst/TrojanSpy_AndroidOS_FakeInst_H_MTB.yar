
rule TrojanSpy_AndroidOS_FakeInst_H_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/FakeInst.H!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 6e 64 72 6f 69 64 5f 61 73 73 65 74 2f 6c 65 67 61 6c 73 31 } //01 00 
		$a_01_1 = {61 6e 64 72 6f 69 64 68 69 74 67 61 6d 65 73 2e 72 75 2f 6c 6f 67 2f 73 74 61 72 74 } //01 00 
		$a_01_2 = {70 72 6f 67 6c 61 79 73 73 5f 43 6c 69 63 6b } //01 00 
		$a_01_3 = {41 6e 78 69 65 74 79 52 65 63 65 69 76 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}