
rule Trojan_BAT_Formbook_PSUC_MTB{
	meta:
		description = "Trojan:BAT/Formbook.PSUC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 02 28 07 00 00 0a 0a 28 08 00 00 0a 06 28 07 00 00 06 6f 09 00 00 0a 0b 2b 00 07 2a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}