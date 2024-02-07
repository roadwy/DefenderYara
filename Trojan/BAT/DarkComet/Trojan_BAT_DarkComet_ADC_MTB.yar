
rule Trojan_BAT_DarkComet_ADC_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.ADC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0d 12 02 12 01 28 90 01 03 06 74 01 00 00 1b 13 04 12 03 12 00 28 90 01 03 06 74 01 00 00 1b 13 05 11 05 28 90 01 03 0a 13 06 11 04 13 07 28 90 01 03 0a 1f 33 8d 02 00 00 01 25 d0 05 00 00 04 28 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_DarkComet_ADC_MTB_2{
	meta:
		description = "Trojan:BAT/DarkComet.ADC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {0b 2b 21 28 90 01 03 0a 09 8e b7 17 da 6b 5a 6b 6c 28 90 01 03 0a b7 13 04 06 09 11 04 93 6f 90 01 03 0a 26 06 6f 90 00 } //01 00 
		$a_01_1 = {46 00 72 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //00 00  Fries.Resources
	condition:
		any of ($a_*)
 
}