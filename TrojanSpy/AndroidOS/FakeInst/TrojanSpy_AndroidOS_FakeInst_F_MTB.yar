
rule TrojanSpy_AndroidOS_FakeInst_F_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/FakeInst.F!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 67 6f 6f 67 6c 65 2f 6d 65 64 69 61 2f 73 69 67 6e 65 72 } //01 00 
		$a_01_1 = {70 61 6e 64 6f 72 61 30 30 2e 72 75 } //01 00 
		$a_01_2 = {41 45 53 63 72 65 65 6e 4f 66 66 52 65 63 65 69 76 65 72 } //01 00 
		$a_01_3 = {53 65 6e 64 55 73 65 72 44 61 74 61 } //01 00 
		$a_01_4 = {43 6f 6e 74 61 63 74 73 33 39 39 35 } //00 00 
	condition:
		any of ($a_*)
 
}