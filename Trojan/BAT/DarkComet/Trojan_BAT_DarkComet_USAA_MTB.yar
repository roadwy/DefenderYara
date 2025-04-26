
rule Trojan_BAT_DarkComet_USAA_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.USAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 0d 74 75 00 00 01 02 28 ?? 00 00 2b 28 ?? 00 00 2b 16 02 8e 69 6f ?? 00 00 0a 1a 13 16 2b c1 11 0d 75 ?? 00 00 01 6f ?? 00 00 0a de 49 } //3
		$a_03_1 = {8d 06 00 00 01 25 16 09 75 22 00 00 1b a2 14 14 16 17 28 ?? 00 00 0a 19 13 11 2b 93 11 05 14 16 03 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}