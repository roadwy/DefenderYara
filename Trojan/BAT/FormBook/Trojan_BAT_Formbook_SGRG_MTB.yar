
rule Trojan_BAT_Formbook_SGRG_MTB{
	meta:
		description = "Trojan:BAT/Formbook.SGRG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 11 07 09 8e 69 5d 91 13 08 07 11 07 91 11 08 61 13 09 11 07 17 58 08 5d 13 0a 07 11 0a 91 13 0b } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}