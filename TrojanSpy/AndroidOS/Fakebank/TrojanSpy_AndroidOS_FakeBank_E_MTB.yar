
rule TrojanSpy_AndroidOS_FakeBank_E_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/FakeBank.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,0e 00 0e 00 06 00 00 05 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 62 6e 6b } //05 00 
		$a_01_1 = {61 63 74 69 76 69 74 79 2e 4d 61 69 6e 41 63 74 69 76 69 74 79 41 } //01 00 
		$a_01_2 = {2e 61 70 6b } //01 00 
		$a_01_3 = {69 6e 73 74 61 6c 6c 5f 6e 6f 6e 5f 6d 61 72 6b 65 74 5f 61 70 70 73 } //01 00 
		$a_01_4 = {61 63 74 69 76 69 74 79 2f 41 70 70 53 74 61 72 74 } //01 00 
		$a_00_5 = {73 74 61 72 74 74 72 61 63 6b 69 6e 67 } //00 00 
	condition:
		any of ($a_*)
 
}