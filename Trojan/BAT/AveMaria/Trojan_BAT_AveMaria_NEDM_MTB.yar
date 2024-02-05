
rule Trojan_BAT_AveMaria_NEDM_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEDM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {09 08 11 04 08 8e 69 5d 91 07 11 04 91 61 d2 6f 90 01 01 00 00 0a 11 04 17 58 13 04 11 04 07 8e 69 32 df 09 6f 90 01 01 00 00 0a 13 05 de 21 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}