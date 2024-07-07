
rule Trojan_BAT_DCRat_ADC_MTB{
	meta:
		description = "Trojan:BAT/DCRat.ADC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 0b 16 0c 07 8e 69 17 59 0d 38 18 00 00 00 07 08 91 13 04 07 08 07 09 91 9c 07 09 11 04 9c 08 17 58 0c 09 17 59 0d 08 09 3f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DCRat_ADC_MTB_2{
	meta:
		description = "Trojan:BAT/DCRat.ADC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {0d 07 09 16 11 05 6f 17 00 00 0a 26 16 13 06 2b 11 09 11 06 09 11 06 91 04 61 d2 9c 11 06 17 58 13 06 11 06 09 8e 69 32 e8 } //2
		$a_01_1 = {44 00 43 00 52 00 61 00 74 00 4c 00 6f 00 61 00 64 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //1 DCRatLoader.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_DCRat_ADC_MTB_3{
	meta:
		description = "Trojan:BAT/DCRat.ADC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {16 2b 24 2b 1c 2b 23 7b 02 00 00 04 1f 31 2b 1d 58 d1 2b 1c 26 2b 20 16 2d 02 17 58 16 2d e2 2b 19 2b 1a 1b 32 df 2a 0a 2b d9 02 2b da 06 2b e0 6f } //1
		$a_03_1 = {26 06 17 58 0a 06 18 32 ad 16 0b 1e 2c f7 07 18 5d 2d 10 02 7b 02 00 00 04 1f 58 6f 90 01 01 00 00 0a 26 2b 0e 02 7b 02 00 00 04 1f 59 6f 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}