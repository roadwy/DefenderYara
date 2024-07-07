
rule Trojan_BAT_Formbook_AKAO_MTB{
	meta:
		description = "Trojan:BAT/Formbook.AKAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 07 07 8e 69 6a 5d d4 91 08 11 07 08 8e 69 6a 5d d4 91 61 07 11 07 17 6a 58 07 8e 69 6a 5d d4 91 59 } //2
		$a_01_1 = {50 72 6f 74 6f 74 79 70 65 2e 44 45 41 43 54 } //1 Prototype.DEACT
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}