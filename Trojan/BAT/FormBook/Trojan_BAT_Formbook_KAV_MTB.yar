
rule Trojan_BAT_Formbook_KAV_MTB{
	meta:
		description = "Trojan:BAT/Formbook.KAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_01_0 = {1a db 11 97 a4 44 53 03 2e 15 4d bf 59 c1 d4 b6 6c 15 83 22 c3 d1 68 e4 68 a0 d1 } //4
		$a_01_1 = {ea 1a a3 bb 26 25 19 44 4e 03 81 a7 b5 59 d1 eb 12 88 37 27 cf e8 5d bb 7e 1a } //3
		$a_01_2 = {4f 6c 6c 79 } //3 Olly
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3) >=10
 
}