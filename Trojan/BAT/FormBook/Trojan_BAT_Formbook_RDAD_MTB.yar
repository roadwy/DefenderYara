
rule Trojan_BAT_Formbook_RDAD_MTB{
	meta:
		description = "Trojan:BAT/Formbook.RDAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 37 00 00 0a 59 d2 9c 11 04 17 58 13 04 11 04 11 07 8e 69 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}