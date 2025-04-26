
rule Trojan_BAT_DarkComet_ALPA_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.ALPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 74 04 00 00 1b 07 8f 14 00 00 01 25 71 14 00 00 01 02 07 1f 10 5d 91 61 d2 81 14 00 00 01 19 0d 38 ?? ff ff ff 07 17 58 0b 18 0d 38 ?? ff ff ff 07 06 74 04 00 00 1b 8e 69 32 17 } //3
		$a_03_1 = {02 8e 69 1f 10 59 8d ?? 00 00 01 0a 02 1f 10 06 75 ?? 00 00 1b 16 06 75 ?? 00 00 1b 8e 69 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}