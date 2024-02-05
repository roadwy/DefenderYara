
rule TrojanSpy_AndroidOS_FakeApp_D_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/FakeApp.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6c 6f 61 64 4c 69 62 72 61 72 79 } //01 00 
		$a_01_1 = {4f 72 74 41 70 70 6c 69 63 61 74 69 6f 6e } //01 00 
		$a_01_2 = {53 74 61 72 42 69 67 41 63 74 69 76 69 74 79 } //01 00 
		$a_01_3 = {67 65 74 43 6c 61 73 73 4c 6f 61 64 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}