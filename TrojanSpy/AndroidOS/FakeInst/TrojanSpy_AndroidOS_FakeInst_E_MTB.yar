
rule TrojanSpy_AndroidOS_FakeInst_E_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/FakeInst.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 65 6e 64 69 6e 67 4c 4f 47 } //01 00 
		$a_01_1 = {74 72 61 74 61 72 4d 65 6e 73 61 6a 65 53 4d 53 } //01 00 
		$a_01_2 = {63 6f 6d 2f 65 73 70 65 6e 67 69 6e 65 2f 68 6f 77 6d 61 6b 65 } //01 00 
		$a_01_3 = {69 6e 69 63 69 6f 50 61 79 65 72 57 65 62 70 69 6e } //00 00 
	condition:
		any of ($a_*)
 
}