
rule Trojan_BAT_Darkcomet_ADET_MTB{
	meta:
		description = "Trojan:BAT/Darkcomet.ADET!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {13 0a 13 08 2b 13 06 11 08 06 11 08 91 07 11 08 91 61 9c 11 08 17 d6 13 08 11 08 11 0a 31 e7 06 28 } //00 00 
	condition:
		any of ($a_*)
 
}