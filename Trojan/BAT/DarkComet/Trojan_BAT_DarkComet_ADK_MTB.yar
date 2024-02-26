
rule Trojan_BAT_DarkComet_ADK_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {16 1f 26 9c 11 05 17 20 dc 00 00 00 9c 11 05 18 20 ff 00 00 00 9c 11 05 19 16 9c 11 05 1a 20 ad 00 00 00 9c 11 05 1b } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_DarkComet_ADK_MTB_2{
	meta:
		description = "Trojan:BAT/DarkComet.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 19 02 06 02 06 91 03 06 7e 90 01 01 00 00 04 5d 91 61 28 90 01 01 00 00 0a 9c 06 17 58 0a 06 02 8e 69 32 e1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_DarkComet_ADK_MTB_3{
	meta:
		description = "Trojan:BAT/DarkComet.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {16 03 8e b7 17 da 13 04 0d 2b 24 03 09 03 09 91 90 01 03 8e b7 5d 91 09 06 d6 07 8e b7 d6 1d 5f 64 d2 20 ff 00 00 00 5f b4 61 9c 09 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_DarkComet_ADK_MTB_4{
	meta:
		description = "Trojan:BAT/DarkComet.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 21 02 50 06 02 50 06 91 7e 01 00 00 04 06 7e 01 00 00 04 8e 69 5d 91 61 28 90 01 03 0a 9c 06 17 58 0a 06 02 50 8e 69 32 d8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_DarkComet_ADK_MTB_5{
	meta:
		description = "Trojan:BAT/DarkComet.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {1f 20 19 15 15 28 90 01 01 00 00 0a 1f 0a 13 07 1b 07 15 6a 16 28 90 01 01 00 00 0a 1f 0b 13 07 17 8d 90 01 01 00 00 01 13 04 11 04 16 1b 9e 11 04 28 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_DarkComet_ADK_MTB_6{
	meta:
		description = "Trojan:BAT/DarkComet.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {13 05 08 25 13 0a 2c 06 11 0a 8e 69 2d 06 16 e0 13 06 2b 0a 11 0a 16 8f 90 01 03 01 13 06 11 05 25 13 0a 2c 06 11 0a 8e 69 2d 06 16 e0 13 07 2b 0a 11 0a 16 8f 90 01 03 01 13 07 11 06 d3 11 07 d3 08 8e 69 11 05 8e 69 28 90 01 03 06 13 04 16 e0 13 07 16 e0 13 06 00 11 04 16 32 0a 11 05 8e 69 11 04 fe 04 2b 01 17 13 0b 11 0b 2d 87 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}