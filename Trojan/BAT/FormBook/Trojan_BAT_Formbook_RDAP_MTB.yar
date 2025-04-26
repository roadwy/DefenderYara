
rule Trojan_BAT_Formbook_RDAP_MTB{
	meta:
		description = "Trojan:BAT/Formbook.RDAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 07 17 59 94 0d 08 07 94 09 59 06 7b 55 00 00 04 8e 69 59 13 04 06 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}