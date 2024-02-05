
rule Trojan_AndroidOS_FakeInst_B_MTB{
	meta:
		description = "Trojan:AndroidOS/FakeInst.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 02 00 "
		
	strings :
		$a_00_0 = {41 75 74 6f 52 75 6e 6e 65 72 2e 6a 61 72 } //01 00 
		$a_00_1 = {63 6f 70 79 41 73 73 65 74 41 70 6b 32 53 74 6f 72 61 67 65 } //01 00 
		$a_00_2 = {73 69 6c 65 6e 74 49 6e 73 74 61 6c 6c } //01 00 
		$a_00_3 = {70 6d 20 69 6e 73 74 61 6c 6c 20 2d 72 } //01 00 
		$a_00_4 = {68 61 73 52 6f 6f 74 50 65 72 73 73 69 6f 6e } //00 00 
		$a_00_5 = {5d 04 00 00 } //3a 80 
	condition:
		any of ($a_*)
 
}