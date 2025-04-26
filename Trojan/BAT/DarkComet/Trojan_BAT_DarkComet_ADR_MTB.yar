
rule Trojan_BAT_DarkComet_ADR_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.ADR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 06 13 05 2b 2d 07 11 05 02 11 05 91 09 61 08 11 04 91 61 b4 9c 11 04 03 6f ?? 00 00 0a 17 da 33 05 16 13 04 2b 06 11 04 17 d6 13 04 11 05 17 d6 13 05 11 05 11 06 31 cd } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkComet_ADR_MTB_2{
	meta:
		description = "Trojan:BAT/DarkComet.ADR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 25 13 06 13 05 16 13 07 2b 5f 11 05 17 58 20 00 01 00 00 5d 13 05 11 06 08 11 05 91 58 20 00 01 00 00 5d 13 06 08 11 05 91 13 04 08 11 05 08 11 06 91 9c 08 11 06 11 04 9c 08 11 05 91 08 11 06 91 58 20 00 01 00 00 5d 13 08 06 11 07 8f 0c 00 00 01 25 71 0c 00 00 01 08 11 08 91 61 d2 81 0c 00 00 01 11 07 17 58 13 07 11 07 06 16 6f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}