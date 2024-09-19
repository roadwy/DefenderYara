
rule Trojan_BAT_DarkComet_ADM_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.ADM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {da 0d 0c 2b 3f 07 08 91 1f 1f fe 02 07 08 91 1f 7f fe 04 5f 2c 14 07 08 13 04 11 04 07 11 04 91 08 1f 1f 5d 18 d6 b4 59 86 9c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkComet_ADM_MTB_2{
	meta:
		description = "Trojan:BAT/DarkComet.ADM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 02 8e b7 17 da 13 06 13 05 2b 29 08 11 05 02 11 05 91 11 04 61 09 07 91 61 b4 9c 07 03 6f ?? 00 00 0a 17 da 33 04 16 0b 2b 04 07 17 d6 0b 11 05 17 d6 13 05 11 05 11 06 31 d1 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkComet_ADM_MTB_3{
	meta:
		description = "Trojan:BAT/DarkComet.ADM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {1f 20 17 19 15 28 ?? 00 00 0a 1a 13 0a 17 28 ?? 00 00 0a b7 28 ?? 00 00 0a 0b 1b 13 0a 17 28 ?? 00 00 0a b7 28 ?? 00 00 0a 13 05 1c 13 0a 17 28 ?? 00 00 0a b7 28 ?? 00 00 0a 13 06 1d 13 0a 17 28 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkComet_ADM_MTB_4{
	meta:
		description = "Trojan:BAT/DarkComet.ADM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 02 8e b7 17 da 13 08 13 07 2b 33 09 11 07 02 11 07 91 11 05 61 11 04 11 06 91 61 9c 11 04 28 ?? ?? ?? 0a 11 06 11 04 8e b7 17 da } //1
		$a_01_1 = {0d 0b 2b 24 16 0c 02 07 94 08 33 0f 06 08 17 da 13 04 11 04 06 11 04 94 17 d6 9e 08 17 d6 0c 08 1f 0a 31 e2 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_BAT_DarkComet_ADM_MTB_5{
	meta:
		description = "Trojan:BAT/DarkComet.ADM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0a 2b 49 72 ?? 00 00 70 06 8c ?? 00 00 01 28 ?? 00 00 0a 0b 07 28 ?? 00 00 0a 6f ?? 00 00 0a 16 9a 0c 08 06 73 ?? 00 00 0a 0d 18 17 1c 73 } //1
		$a_03_1 = {16 0a 2b 1f 7e ?? 00 00 04 06 7e ?? 00 00 04 5d 91 0b 02 06 02 06 91 07 61 28 ?? 00 00 0a 9c 06 17 58 0a 06 02 8e 69 32 db } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}