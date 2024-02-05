
rule Trojan_BAT_DarkComet_ADK_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 21 02 50 06 02 50 06 91 7e 01 00 00 04 06 7e 01 00 00 04 8e 69 5d 91 61 28 90 01 03 0a 9c 06 17 58 0a 06 02 50 8e 69 32 d8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_DarkComet_ADK_MTB_2{
	meta:
		description = "Trojan:BAT/DarkComet.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {13 05 08 25 13 0a 2c 06 11 0a 8e 69 2d 06 16 e0 13 06 2b 0a 11 0a 16 8f 90 01 03 01 13 06 11 05 25 13 0a 2c 06 11 0a 8e 69 2d 06 16 e0 13 07 2b 0a 11 0a 16 8f 90 01 03 01 13 07 11 06 d3 11 07 d3 08 8e 69 11 05 8e 69 28 90 01 03 06 13 04 16 e0 13 07 16 e0 13 06 00 11 04 16 32 0a 11 05 8e 69 11 04 fe 04 2b 01 17 13 0b 11 0b 2d 87 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}