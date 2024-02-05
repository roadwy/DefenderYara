
rule Trojan_AndroidOS_FakeInst_O_MTB{
	meta:
		description = "Trojan:AndroidOS/FakeInst.O!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 65 74 4d 6f 62 69 65 6c 4e 6f } //01 00 
		$a_01_1 = {48 69 64 65 4d 65 73 73 61 67 65 } //01 00 
		$a_01_2 = {52 65 76 65 72 73 65 4f 6e 42 6f 61 72 64 } //01 00 
		$a_01_3 = {61 6e 64 72 6f 69 64 68 69 74 67 61 6d 65 73 2e 72 75 2f 6c 6f 67 2f 6d 73 67 } //01 00 
		$a_01_4 = {57 72 69 74 65 50 68 6f 6e 65 50 72 65 66 } //00 00 
	condition:
		any of ($a_*)
 
}