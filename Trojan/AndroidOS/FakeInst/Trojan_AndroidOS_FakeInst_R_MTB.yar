
rule Trojan_AndroidOS_FakeInst_R_MTB{
	meta:
		description = "Trojan:AndroidOS/FakeInst.R!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 6d 73 5f 74 68 72 65 61 64 5f 76 65 72 73 69 6f 6e 31 } //01 00 
		$a_01_1 = {63 68 65 63 6b 5f 41 6c 69 76 65 } //01 00 
		$a_01_2 = {73 6d 73 72 65 63 65 69 76 65 61 6e 64 6d 61 73 6b } //01 00 
		$a_01_3 = {63 6f 6d 2f 78 6d 6f 62 69 6c 65 61 70 70 2f 53 6e 61 6b 65 5f 6c 76 } //00 00 
	condition:
		any of ($a_*)
 
}