
rule Trojan_BAT_Formbook_RDAI_MTB{
	meta:
		description = "Trojan:BAT/Formbook.RDAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 05 74 40 00 00 1b 6f 04 01 00 0a 28 0f 00 00 2b 28 10 00 00 2b 0a 06 74 41 00 00 1b 2a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}