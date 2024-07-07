
rule Trojan_BAT_Formbook_KAK_MTB{
	meta:
		description = "Trojan:BAT/Formbook.KAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 17 58 11 90 01 01 5d 13 90 01 01 07 08 91 11 90 01 01 61 07 11 90 01 01 91 59 20 00 01 00 00 58 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}