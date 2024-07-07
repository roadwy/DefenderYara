
rule Trojan_BAT_DarkComet_ADC_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.ADC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 2c 02 2b 50 72 90 01 01 00 00 70 28 90 01 01 00 00 0a 73 90 01 01 00 00 0a 0c 08 28 90 01 01 00 00 0a 17 17 6f 90 01 01 00 00 0a 0b 08 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkComet_ADC_MTB_2{
	meta:
		description = "Trojan:BAT/DarkComet.ADC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 06 11 06 16 08 a2 11 06 17 03 16 9a 74 90 01 01 00 00 1b a2 11 06 18 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a a2 11 06 6f 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkComet_ADC_MTB_3{
	meta:
		description = "Trojan:BAT/DarkComet.ADC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 06 0d 16 0c 2b 2b 09 08 9a 0b 07 6f 90 01 01 00 00 0a 72 90 01 01 0d 00 70 6f 90 01 01 00 00 0a 13 04 11 04 2c 0b 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 00 00 08 17 d6 0c 00 08 09 8e 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkComet_ADC_MTB_4{
	meta:
		description = "Trojan:BAT/DarkComet.ADC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 12 02 12 01 28 90 01 03 06 74 01 00 00 1b 13 04 12 03 12 00 28 90 01 03 06 74 01 00 00 1b 13 05 11 05 28 90 01 03 0a 13 06 11 04 13 07 28 90 01 03 0a 1f 33 8d 02 00 00 01 25 d0 05 00 00 04 28 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkComet_ADC_MTB_5{
	meta:
		description = "Trojan:BAT/DarkComet.ADC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0c 2b 48 06 17 d6 20 ff 00 00 00 5f 0a 07 11 05 06 91 d6 20 ff 00 00 00 5f 0b 11 05 06 91 13 07 11 05 06 11 05 07 91 9c 11 05 07 11 07 9c 09 08 11 05 11 05 06 91 11 05 07 91 d6 20 ff 00 00 00 5f 91 02 08 91 61 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkComet_ADC_MTB_6{
	meta:
		description = "Trojan:BAT/DarkComet.ADC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0b 2b 21 28 90 01 03 0a 09 8e b7 17 da 6b 5a 6b 6c 28 90 01 03 0a b7 13 04 06 09 11 04 93 6f 90 01 03 0a 26 06 6f 90 00 } //2
		$a_01_1 = {46 00 72 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 Fries.Resources
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}