
rule Trojan_BAT_DarkTortilla_GGZ_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.GGZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_01_0 = {04 1b 5d 2c 03 03 2b 07 03 20 ee 00 00 00 61 b4 0a 2b 00 06 2a } //5
		$a_03_1 = {2b 16 7e 56 00 00 04 fe 06 ab 00 00 06 73 7c 00 00 0a 25 80 57 00 00 04 28 ?? 00 00 2b 28 ?? 00 00 2b 0b 00 7e 58 00 00 04 2c 07 7e 58 00 00 04 2b 16 7e 56 00 00 04 fe 06 ac 00 00 06 73 7f 00 00 0a 25 80 58 00 00 04 0d 72 75 11 00 70 28 ?? 00 00 0a 13 04 11 04 14 fe 01 13 06 11 06 2c 0b } //4
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*4) >=9
 
}