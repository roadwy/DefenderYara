
rule Trojan_BAT_Formbook_MCB_MTB{
	meta:
		description = "Trojan:BAT/Formbook.MCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 52 00 65 00 66 00 6c 00 65 00 63 00 74 00 69 00 6f 00 6e 00 2e 00 41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 00 0d 20 00 4c 00 6f 00 61 00 64 } //1
		$a_01_1 = {36 00 44 00 35 00 38 00 36 00 39 00 37 00 34 00 00 0d 37 00 41 00 36 00 31 00 37 00 41 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}