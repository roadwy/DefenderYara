
rule Trojan_BAT_Darkcomet_ACZA_MTB{
	meta:
		description = "Trojan:BAT/Darkcomet.ACZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 05 11 07 11 05 11 07 91 06 11 06 25 17 58 13 06 91 61 d2 9c 11 06 06 8e 69 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}