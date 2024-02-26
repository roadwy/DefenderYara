
rule Trojan_BAT_DarkKomet_CHAA_MTB{
	meta:
		description = "Trojan:BAT/DarkKomet.CHAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {03 11 06 11 04 6f 90 01 01 00 00 0a 13 05 06 08 19 d8 18 d6 12 05 28 90 01 01 00 00 0a 9c 06 08 19 d8 17 d6 12 05 28 90 01 01 00 00 0a 9c 06 08 19 d8 12 05 28 90 01 01 00 00 0a 9c 08 17 d6 0c 11 06 17 d6 13 06 11 06 11 07 31 bc 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}