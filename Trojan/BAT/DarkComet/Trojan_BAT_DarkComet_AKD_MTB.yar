
rule Trojan_BAT_DarkComet_AKD_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.AKD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0c 0b 2b 24 02 07 02 07 91 02 07 17 d6 02 8e b7 5d 91 d6 20 00 01 00 00 5d b4 03 07 03 8e b7 5d 91 61 9c 00 07 17 d6 0b 07 08 0d 09 31 d6 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkComet_AKD_MTB_2{
	meta:
		description = "Trojan:BAT/DarkComet.AKD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 16 0b 2b 43 16 0c 2b 35 06 08 06 08 91 03 08 03 8e 69 5d 91 61 d2 9c 16 0d 2b 18 06 08 06 08 91 03 09 91 07 1f 1f 5f 62 09 61 08 58 61 d2 9c 09 17 58 0d 09 03 8e 69 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkComet_AKD_MTB_3{
	meta:
		description = "Trojan:BAT/DarkComet.AKD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 17 58 20 00 01 00 00 5d 0b 11 05 11 08 07 91 58 20 00 01 00 00 5d 13 05 11 08 07 91 13 0d 11 08 07 11 08 11 05 91 9c 11 08 11 05 11 0d 9c 11 08 07 91 11 08 11 05 91 58 d2 20 00 01 00 00 5d 13 0c 02 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkComet_AKD_MTB_4{
	meta:
		description = "Trojan:BAT/DarkComet.AKD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 0a 11 09 07 94 d6 11 06 07 94 d6 20 00 01 00 00 5d 13 0a 11 09 07 94 13 0c 11 09 07 11 09 11 0a 94 9e 11 09 11 0a 11 0c 9e 7e ?? 00 00 04 7e ?? 00 00 04 12 01 28 ?? 00 00 06 07 17 da 28 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkComet_AKD_MTB_5{
	meta:
		description = "Trojan:BAT/DarkComet.AKD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0d 16 0c 2b 37 09 08 9a 0b 07 72 ?? 09 00 70 72 ?? 09 00 70 28 ?? 00 00 06 6f ?? 00 00 0a 2c 18 07 72 ?? 09 00 70 72 ?? 09 00 70 28 ?? 00 00 06 28 ?? 00 00 0a 0a 2b 0a 08 17 d6 0c 08 } //2
		$a_01_1 = {17 da 32 02 2b 2d 08 09 8e b7 32 02 16 0c 11 06 11 07 93 13 08 09 08 93 13 09 11 08 11 05 da 11 09 da 13 0a 07 11 07 11 0a 28 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}