
rule Trojan_BAT_Formbook_RDAU_MTB{
	meta:
		description = "Trojan:BAT/Formbook.RDAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 03 6f 49 00 00 0a 8e 69 6f 4d 00 00 0a 28 08 00 00 2b 2a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}