
rule Trojan_AndroidOS_FakeInst_G_MTB{
	meta:
		description = "Trojan:AndroidOS/FakeInst.G!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 75 74 6f 70 61 79 5f 73 65 73 73 69 6f 6e } //01 00 
		$a_01_1 = {73 6d 73 5f 65 78 74 72 61 } //01 00 
		$a_01_2 = {64 61 74 61 2e 72 65 73 } //01 00 
		$a_01_3 = {61 67 72 65 65 6d 65 6e 74 5f 74 65 78 74 } //01 00 
		$a_01_4 = {72 61 74 65 73 2e 70 68 70 } //00 00 
	condition:
		any of ($a_*)
 
}