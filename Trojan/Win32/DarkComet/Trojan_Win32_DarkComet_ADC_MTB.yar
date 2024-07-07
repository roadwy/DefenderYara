
rule Trojan_Win32_DarkComet_ADC_MTB{
	meta:
		description = "Trojan:Win32/DarkComet.ADC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {51 50 6a 00 0f 29 84 24 90 01 04 ff d7 6a 00 6a 00 6a 00 8d 84 24 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_DarkComet_ADC_MTB_2{
	meta:
		description = "Trojan:Win32/DarkComet.ADC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 8b 45 fc e8 39 4d f8 ff 50 a1 d8 87 4a 00 50 } //1
		$a_01_1 = {6a 00 6a 00 6a 00 6a 00 68 e4 0b 48 00 e8 5c e8 fa ff } //1
		$a_01_2 = {8d 45 f8 50 6a 00 53 68 68 09 49 00 6a 00 6a 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}