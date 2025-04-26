
rule Trojan_BAT_DarkTortilla_ARCA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.ARCA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 1f 18 5d 16 fe 01 0b 07 2c 04 14 0a 2b 2a 00 02 19 d8 10 00 02 1f 18 fe 02 0c 08 2c 11 1f 18 10 00 72 0e 3b 00 70 28 ?? 01 00 06 0a 2b 0a 00 02 28 ?? 02 00 06 0a 2b 00 06 2a } //3
		$a_03_1 = {0a 72 2d 21 00 70 17 8d ?? 00 00 01 25 16 02 a2 25 0c 14 14 17 8d ?? 00 00 01 25 16 17 9c 25 0d 28 ?? 00 00 0a 09 16 91 2d 02 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}