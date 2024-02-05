
rule Trojan_AndroidOS_FakeInst_E_MTB{
	meta:
		description = "Trojan:AndroidOS/FakeInst.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {4f 70 65 72 61 20 4d 69 6e 69 20 4e 45 57 5f 45 57 5f 45 57 } //01 00 
		$a_00_1 = {73 6d 73 5f 6e 75 6d } //01 00 
		$a_00_2 = {73 74 69 6d 75 6c 70 72 65 6d 69 75 6d 2e 63 6f 6d 2f 72 75 6c 65 73 2e 70 68 70 } //01 00 
		$a_00_3 = {4d 41 58 5f 53 4d 53 5f 4d 45 53 53 41 47 45 } //01 00 
		$a_00_4 = {6d 6f 62 69 6c 65 2d 70 72 65 6d 69 75 6d 2e 63 6f 6d } //00 00 
	condition:
		any of ($a_*)
 
}