
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
		description = "Trojan:BAT/DarkComet.ADT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b 3a 06 11 06 11 07 94 d6 09 11 07 94 d6 20 00 01 00 00 5d 0a 11 06 11 07 94 13 0c 11 06 11 07 11 06 06 94 9e 11 06 06 11 0c 9e 12 07 28 ?? 00 00 0a 11 07 17 da 28 } //1
		$a_03_1 = {08 94 11 06 11 0a 94 d6 20 00 01 00 00 5d 94 13 0f 02 11 05 17 da 17 6f ?? 00 00 0a 6f ?? 00 00 0a 16 93 13 0e 11 0e 28 ?? 00 00 0a 13 10 11 10 11 0f 61 13 0d 11 04 11 0d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}