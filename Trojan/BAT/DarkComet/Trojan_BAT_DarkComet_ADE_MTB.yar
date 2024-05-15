
rule Trojan_BAT_DarkComet_ADE_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.ADE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {94 d6 09 11 08 94 d6 20 00 01 00 00 5d 0a 11 07 11 08 94 13 0c 11 07 11 08 11 07 06 94 9e 11 07 06 11 0c 9e 12 08 28 90 01 03 0a 11 08 17 da 28 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_DarkComet_ADE_MTB_2{
	meta:
		description = "Trojan:BAT/DarkComet.ADE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {1f 20 17 19 15 28 90 01 01 00 00 0a 02 17 28 90 01 01 00 00 0a b7 28 90 01 01 00 00 0a 7d 90 01 01 00 00 04 17 02 7c 90 01 01 00 00 04 15 6a 16 28 90 01 01 00 00 0a 17 8d 90 01 01 00 00 01 13 0b 11 0b 16 17 9e 11 0b 28 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}