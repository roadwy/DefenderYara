
rule Trojan_BAT_Formbook_PSPF_MTB{
	meta:
		description = "Trojan:BAT/Formbook.PSPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 72 18 1c 00 70 0a 06 72 56 1c 00 70 28 90 01 03 06 28 90 01 03 0a 28 90 01 03 0a 28 90 01 03 06 0b 07 0c 2b 00 08 2a 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}