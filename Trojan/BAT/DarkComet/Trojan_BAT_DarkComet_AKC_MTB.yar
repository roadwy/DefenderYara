
rule Trojan_BAT_DarkComet_AKC_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.AKC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 13 04 2b 33 09 11 04 9a 26 03 03 0e 04 05 58 6f ?? 00 00 0a 0b 07 1f fb 2e 17 03 0e 04 04 8e 69 58 07 0e 04 59 04 8e 69 59 6f ?? 00 00 0a 0c de 32 11 04 17 58 13 04 11 04 09 8e 69 } //2
		$a_01_1 = {06 13 05 16 13 06 2b 11 11 05 11 06 9a 26 05 19 58 10 03 11 06 17 58 13 06 11 06 11 05 8e 69 32 e7 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}