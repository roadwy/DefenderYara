
rule Trojan_BAT_DarkTortilla_ZFAA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.ZFAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {04 1d 5d 2c 03 03 2b 04 03 1f 4f 61 b4 0a 2b 00 06 2a } //3
		$a_03_1 = {08 14 72 79 23 00 70 16 8d 06 00 00 01 14 14 14 28 ?? 00 00 0a 74 ?? 00 00 01 6f ?? 00 00 0a 13 08 2b 41 11 08 6f ?? 00 00 0a 28 ?? 00 00 0a 13 09 00 11 09 14 72 8f 23 00 70 18 8d 06 00 00 01 25 17 16 8d 06 00 00 01 a2 14 14 14 17 28 ?? 00 00 0a 26 de 1c } //2
	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}