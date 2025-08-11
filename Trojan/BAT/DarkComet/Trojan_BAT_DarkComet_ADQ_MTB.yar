
rule Trojan_BAT_DarkComet_ADQ_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.ADQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {94 09 11 05 94 d6 20 00 01 00 00 5d 94 13 0d 02 06 17 da 17 6f ?? 00 00 0a 6f ?? 00 00 0a 16 93 13 10 11 10 28 ?? 00 00 0a 13 0f 11 0f 11 0d 61 13 0e 11 04 11 0e 28 } //2
		$a_03_1 = {09 07 94 d6 11 07 07 94 d6 20 00 01 00 00 5d 13 09 09 07 94 13 0c 09 07 09 11 09 94 9e 09 11 09 11 0c 9e 12 01 28 ?? 00 00 0a 07 17 da 28 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}