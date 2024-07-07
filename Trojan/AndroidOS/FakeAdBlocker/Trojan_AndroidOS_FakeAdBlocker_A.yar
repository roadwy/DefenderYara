
rule Trojan_AndroidOS_FakeAdBlocker_A{
	meta:
		description = "Trojan:AndroidOS/FakeAdBlocker.A,SIGNATURE_TYPE_DEXHSTR_EXT,14 00 14 00 04 00 00 "
		
	strings :
		$a_01_0 = {4c 63 6f 6d 2f 63 6f 6c 64 2f 74 6f 6f 74 68 62 72 75 73 68 2f 63 74 72 6c 3b } //5 Lcom/cold/toothbrush/ctrl;
		$a_00_1 = {2f 73 76 63 3b } //5 /svc;
		$a_00_2 = {2f 63 6f 6c 64 2f 74 6f 6f 74 68 62 72 75 73 68 2f 62 75 72 } //5 /cold/toothbrush/bur
		$a_01_3 = {2f 44 65 63 72 79 70 74 53 74 72 69 6e 67 3b } //5 /DecryptString;
	condition:
		((#a_01_0  & 1)*5+(#a_00_1  & 1)*5+(#a_00_2  & 1)*5+(#a_01_3  & 1)*5) >=20
 
}