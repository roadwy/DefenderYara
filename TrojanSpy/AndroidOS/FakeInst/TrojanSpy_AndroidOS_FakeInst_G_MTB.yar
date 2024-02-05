
rule TrojanSpy_AndroidOS_FakeInst_G_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/FakeInst.G!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 65 69 63 68 5f 53 65 72 76 65 72 47 61 74 65 } //01 00 
		$a_01_1 = {67 65 74 4d 65 73 73 61 67 65 73 3a 45 78 65 63 75 74 65 64 3a 48 54 54 50 } //01 00 
		$a_01_2 = {4c 63 6f 6d 2f 61 64 6f 62 65 2f } //01 00 
		$a_01_3 = {44 65 76 69 63 65 41 64 6d 69 6e 41 64 64 } //01 00 
		$a_01_4 = {42 6f 74 4c 6f 63 61 74 69 6f 6e } //00 00 
	condition:
		any of ($a_*)
 
}