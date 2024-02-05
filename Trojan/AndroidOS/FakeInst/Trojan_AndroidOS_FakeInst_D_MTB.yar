
rule Trojan_AndroidOS_FakeInst_D_MTB{
	meta:
		description = "Trojan:AndroidOS/FakeInst.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {4d 79 53 4d 53 4d 6f 6e 69 74 6f 72 } //01 00 
		$a_00_1 = {53 4d 53 20 69 73 20 64 65 6c 65 74 65 64 } //01 00 
		$a_00_2 = {69 6e 62 6f 78 20 69 73 20 61 64 64 65 64 } //01 00 
		$a_00_3 = {69 4d 54 43 50 61 79 } //01 00 
		$a_00_4 = {4c 63 6f 6d 2f 61 6e 64 72 6f 69 64 69 6e 73 74 61 6c 6c 2f 63 6c 69 65 6e 74 2f 4c 69 63 65 6e 7a 65 } //01 00 
		$a_00_5 = {73 65 6e 74 62 6f 78 20 69 73 20 61 64 64 65 64 } //00 00 
	condition:
		any of ($a_*)
 
}