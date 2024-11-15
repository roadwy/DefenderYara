
rule Trojan_BAT_DarkTortilla_YHAA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.YHAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a a2 25 17 17 8c 64 00 00 01 a2 25 18 17 8c 64 00 00 01 a2 25 13 04 14 14 19 8d 64 00 00 01 25 16 17 9c 25 13 05 28 ?? 00 00 0a 13 06 11 05 16 91 2d 02 2b 23 11 04 16 9a } //3
		$a_03_1 = {01 11 0c 16 11 0c 8e 69 6f ?? 01 00 0a 13 0d 11 0d 16 fe 02 13 0f 11 0f 2c 0e 11 0b 11 0c 16 11 0d 6f ?? 01 00 0a 00 00 00 00 11 0d 16 fe 02 13 10 11 10 2d c5 11 0b 6f ?? 01 00 0a 13 0e 11 0e 28 ?? 01 00 0a 00 11 0e 0a 2b 05 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}