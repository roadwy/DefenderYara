
rule Trojan_BAT_DarkComet_ADC_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.ADC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 0a 2b 1a 00 02 06 7e 04 00 00 04 06 91 03 06 0e 04 8e 69 5d 91 61 d2 9c 00 06 17 58 0a 06 7e 04 00 00 04 8e 69 fe 04 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkComet_ADC_MTB_2{
	meta:
		description = "Trojan:BAT/DarkComet.ADC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 2c 02 2b 50 72 ?? 00 00 70 28 ?? 00 00 0a 73 ?? 00 00 0a 0c 08 28 ?? 00 00 0a 17 17 6f ?? 00 00 0a 0b 08 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkComet_ADC_MTB_3{
	meta:
		description = "Trojan:BAT/DarkComet.ADC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 06 11 06 16 08 a2 11 06 17 03 16 9a 74 ?? 00 00 1b a2 11 06 18 28 ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a a2 11 06 6f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkComet_ADC_MTB_4{
	meta:
		description = "Trojan:BAT/DarkComet.ADC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 06 0d 16 0c 2b 2b 09 08 9a 0b 07 6f ?? 00 00 0a 72 ?? 0d 00 70 6f ?? 00 00 0a 13 04 11 04 2c 0b 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 08 17 d6 0c 00 08 09 8e } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkComet_ADC_MTB_5{
	meta:
		description = "Trojan:BAT/DarkComet.ADC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 12 02 12 01 28 ?? ?? ?? 06 74 01 00 00 1b 13 04 12 03 12 00 28 ?? ?? ?? 06 74 01 00 00 1b 13 05 11 05 28 ?? ?? ?? 0a 13 06 11 04 13 07 28 ?? ?? ?? 0a 1f 33 8d 02 00 00 01 25 d0 05 00 00 04 28 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkComet_ADC_MTB_6{
	meta:
		description = "Trojan:BAT/DarkComet.ADC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0c 2b 48 06 17 d6 20 ff 00 00 00 5f 0a 07 11 05 06 91 d6 20 ff 00 00 00 5f 0b 11 05 06 91 13 07 11 05 06 11 05 07 91 9c 11 05 07 11 07 9c 09 08 11 05 11 05 06 91 11 05 07 91 d6 20 ff 00 00 00 5f 91 02 08 91 61 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkComet_ADC_MTB_7{
	meta:
		description = "Trojan:BAT/DarkComet.ADC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0b 2b 21 28 ?? ?? ?? 0a 09 8e b7 17 da 6b 5a 6b 6c 28 ?? ?? ?? 0a b7 13 04 06 09 11 04 93 6f ?? ?? ?? 0a 26 06 6f } //2
		$a_01_1 = {46 00 72 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 Fries.Resources
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_DarkComet_ADC_MTB_8{
	meta:
		description = "Trojan:BAT/DarkComet.ADC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0d 0c 2b 49 07 08 91 1f 1f fe 02 07 08 91 1f 7f fe 04 5f 2c 19 07 13 04 11 04 08 13 05 11 05 11 04 11 05 91 08 1f 1f 5d 18 d6 b4 59 86 9c 07 08 91 1f 20 2f 14 07 13 04 11 04 08 13 05 11 05 11 04 11 05 91 1f 5f 58 86 9c 08 17 d6 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkComet_ADC_MTB_9{
	meta:
		description = "Trojan:BAT/DarkComet.ADC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {16 02 50 8e b7 17 da 0c 0b 2b 37 02 50 07 02 50 8e b7 5d 02 50 07 02 50 8e b7 5d 91 03 07 03 8e b7 5d 91 61 02 50 07 17 d6 02 50 8e b7 5d 91 da 20 00 01 00 00 d6 20 00 01 00 00 5d b4 9c 07 17 d6 0b 07 08 31 c5 } //2
		$a_01_1 = {54 00 68 00 65 00 45 00 6c 00 65 00 76 00 61 00 74 00 6f 00 72 00 2e 00 74 00 78 00 74 00 } //1 TheElevator.txt
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_DarkComet_ADC_MTB_10{
	meta:
		description = "Trojan:BAT/DarkComet.ADC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 16 03 6f ?? 00 00 0a 17 da 13 05 0c 2b 61 16 03 6f ?? 00 00 0a 17 da 13 06 13 04 2b 48 03 08 11 04 6f ?? 00 00 0a 0d 09 16 16 16 16 28 ?? 00 00 0a 28 ?? 00 00 0a 2c 27 06 12 03 28 ?? 00 00 0a 6f ?? 00 00 0a 06 12 03 28 ?? 00 00 0a 6f ?? 00 00 0a 06 12 03 28 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkComet_ADC_MTB_11{
	meta:
		description = "Trojan:BAT/DarkComet.ADC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 06 17 da 17 6f ?? 00 00 0a 6f ?? 00 00 0a 16 93 13 0e 11 0e 28 ?? 00 00 0a 13 0f 11 0f 11 10 61 13 0d 38 6e 01 00 00 11 05 11 09 09 94 d6 20 00 01 00 00 5d 13 05 } //2
		$a_01_1 = {11 09 09 94 13 0f 11 09 09 11 09 11 05 94 9e 11 09 11 05 11 0f 9e 11 09 11 09 09 94 11 09 11 05 94 d6 20 00 01 00 00 5d 94 13 10 fe 0c 01 00 6d 16 5f 16 fe 01 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_DarkComet_ADC_MTB_12{
	meta:
		description = "Trojan:BAT/DarkComet.ADC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {0a 06 0d 16 0c 2b 2b 09 08 9a 0b 07 6f ?? 00 00 0a 72 ?? 01 00 70 6f ?? 00 00 0a 13 04 11 04 2c 0b 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 08 17 d6 0c 00 08 09 8e } //2
		$a_01_1 = {43 00 72 00 79 00 70 00 6f 00 6f 00 53 00 53 00 } //1 CrypooSS
		$a_01_2 = {53 00 62 00 69 00 65 00 43 00 74 00 72 00 6c 00 } //1 SbieCtrl
		$a_01_3 = {44 00 6f 00 6c 00 6c 00 44 00 6c 00 6c 00 } //1 DollDll
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}