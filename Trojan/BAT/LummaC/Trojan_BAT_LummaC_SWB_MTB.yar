
rule Trojan_BAT_LummaC_SWB_MTB{
	meta:
		description = "Trojan:BAT/LummaC.SWB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 05 11 07 1f 28 5a 58 13 08 28 1e 00 00 0a 07 11 08 1e 6f 1f 00 00 0a 17 8d 20 00 00 01 6f 20 00 00 0a 13 09 11 09 72 01 00 00 70 28 21 00 00 0a 2c 3e 07 11 08 1f 14 58 28 1d 00 00 0a 13 0a 07 11 08 1f 10 58 28 1d 00 00 0a 13 0b 11 0b 8d 17 00 00 01 80 04 00 00 04 07 11 0a 6e 7e 04 00 00 04 16 6a 11 0b 6e 28 22 00 00 0a 17 13 06 de 31 de 21 25 6f 23 00 00 0a 28 24 00 00 0a 6f 23 00 00 0a 25 2d 06 26 72 0b 00 00 70 28 25 00 00 0a 26 de 00 11 07 17 58 13 07 11 07 09 3f 5e ff ff ff } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}