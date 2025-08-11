
rule Trojan_BAT_DarkComet_ADT_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.ADT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 02 8e b7 17 59 0c 0b 2b 0f 02 07 02 07 91 1f 0b 61 d2 9c 07 1f 0b 58 0b 07 08 31 ed } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkComet_ADT_MTB_2{
	meta:
		description = "Trojan:BAT/DarkComet.ADT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 16 0c 2b 18 07 08 03 08 91 06 20 00 01 00 00 6f ?? 00 00 0a d2 61 d2 9c 08 17 58 0c 08 03 8e 69 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkComet_ADT_MTB_3{
	meta:
		description = "Trojan:BAT/DarkComet.ADT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 13 08 2b 25 11 06 11 08 11 04 11 08 91 11 05 11 08 11 05 8e 69 5d 91 11 07 58 20 ff 00 00 00 5f 61 d2 9c 11 08 17 58 13 08 11 08 11 06 8e 69 17 59 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkComet_ADT_MTB_4{
	meta:
		description = "Trojan:BAT/DarkComet.ADT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {5d 0a 11 05 11 09 91 13 04 11 05 11 09 11 05 06 91 9c 11 05 06 11 04 9c 11 05 11 09 91 11 05 06 91 d6 20 00 01 00 00 5d 0b 03 50 11 0a 03 50 11 0a 91 11 05 07 91 61 9c 11 0a 17 d6 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkComet_ADT_MTB_5{
	meta:
		description = "Trojan:BAT/DarkComet.ADT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 06 0d 2b 47 02 08 09 6f ?? 00 00 0a 13 04 11 04 16 16 16 16 28 ?? 00 00 0a 28 ?? 00 00 0a 2c 27 07 12 04 28 ?? 00 00 0a 6f ?? 00 00 0a 07 12 04 28 ?? 00 00 0a 6f } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_BAT_DarkComet_ADT_MTB_6{
	meta:
		description = "Trojan:BAT/DarkComet.ADT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {09 11 05 08 11 05 8e b7 5d 91 d6 11 07 08 91 d6 20 ff 00 00 00 5f 0d 11 07 08 91 13 08 11 07 08 11 07 09 91 9c 11 07 09 11 08 9c 08 17 d6 0c 08 11 0c } //2
		$a_01_1 = {0c 09 11 07 08 91 d6 20 ff 00 00 00 5f 0d 11 07 08 91 13 09 11 07 08 11 07 09 91 9c 11 07 09 11 09 9c 11 06 11 04 11 07 11 07 08 91 11 07 09 91 d6 20 ff 00 00 00 5f 91 06 11 04 91 61 9c 11 04 17 d6 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_DarkComet_ADT_MTB_7{
	meta:
		description = "Trojan:BAT/DarkComet.ADT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b 3a 06 11 06 11 07 94 d6 09 11 07 94 d6 20 00 01 00 00 5d 0a 11 06 11 07 94 13 0c 11 06 11 07 11 06 06 94 9e 11 06 06 11 0c 9e 12 07 28 ?? 00 00 0a 11 07 17 da 28 } //1
		$a_03_1 = {08 94 11 06 11 0a 94 d6 20 00 01 00 00 5d 94 13 0f 02 11 05 17 da 17 6f ?? 00 00 0a 6f ?? 00 00 0a 16 93 13 0e 11 0e 28 ?? 00 00 0a 13 10 11 10 11 0f 61 13 0d 11 04 11 0d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}