
rule Trojan_BAT_AveMaria_NEDU_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEDU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0d 16 13 04 2b 1e 09 06 11 04 06 8e 69 5d 91 08 11 04 91 61 d2 6f 90 01 01 00 00 0a 11 04 13 05 11 05 17 58 13 04 11 04 08 8e 69 32 db 09 6f 90 01 01 00 00 0a 13 06 de 1b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}