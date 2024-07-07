
rule Trojan_BAT_Formbook_NZ_MTB{
	meta:
		description = "Trojan:BAT/Formbook.NZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {57 15 a2 09 09 0f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 83 00 00 00 10 00 00 00 32 01 00 00 f6 02 00 00 4f } //1
		$a_01_1 = {02 00 00 d6 00 00 00 90 05 00 00 36 00 00 00 0c 00 00 00 22 01 00 00 3b 02 00 00 0a 00 00 00 01 00 00 00 06 00 00 00 08 00 00 00 02 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}