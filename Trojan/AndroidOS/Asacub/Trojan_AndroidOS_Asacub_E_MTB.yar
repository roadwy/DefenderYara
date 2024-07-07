
rule Trojan_AndroidOS_Asacub_E_MTB{
	meta:
		description = "Trojan:AndroidOS/Asacub.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6d 79 6f 77 6e 62 65 68 61 70 } //1 myownbehap
		$a_01_1 = {63 6f 6d 2e 70 65 74 74 79 2e 61 63 63 6f 75 6e 74 } //1 com.petty.account
		$a_01_2 = {52 68 65 73 73 65 42 79 } //1 RhesseBy
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}