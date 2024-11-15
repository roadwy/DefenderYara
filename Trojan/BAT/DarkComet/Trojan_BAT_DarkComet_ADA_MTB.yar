
rule Trojan_BAT_DarkComet_ADA_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.ADA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0c 02 02 8e b7 17 da 91 1f 70 61 0d 02 8e b7 17 d6 8d 1e 00 00 01 0b 16 02 8e b7 17 da 13 06 13 05 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkComet_ADA_MTB_2{
	meta:
		description = "Trojan:BAT/DarkComet.ADA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 17 59 32 02 2b 2d 07 08 8e b7 32 02 16 0b 11 06 11 07 93 13 0a 08 07 93 13 08 11 0a 09 59 11 08 59 13 09 11 05 11 07 11 09 28 ?? 00 00 0a 9d 07 17 58 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkComet_ADA_MTB_3{
	meta:
		description = "Trojan:BAT/DarkComet.ADA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 02 8e 69 0d 02 8e 69 18 5a 06 8e 69 58 13 04 38 2f 00 00 00 11 04 17 58 0c 02 11 04 09 5d 02 11 04 09 5d 91 06 11 04 06 8e 69 5d 91 61 02 08 09 5d 91 28 ?? 00 00 06 07 58 07 5d d2 9c 11 04 15 58 13 04 11 04 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkComet_ADA_MTB_4{
	meta:
		description = "Trojan:BAT/DarkComet.ADA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 07 2b 3a 09 11 07 02 11 07 91 07 61 08 11 04 91 61 9c 08 28 ?? ?? ?? 0a 00 11 04 08 8e 69 17 da fe 01 16 fe 01 13 08 11 08 2d 05 16 13 04 2b 07 00 11 04 17 d6 13 04 11 07 17 d6 13 07 11 07 11 06 fe 02 16 fe 01 13 08 11 08 2d b7 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}