
rule Trojan_BAT_DarkTortilla_ZBT_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.ZBT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {04 1e 5d 2c 03 03 2b 07 03 20 db 00 00 00 61 b4 0a 2b 00 06 2a } //6
		$a_03_1 = {11 05 17 d6 13 05 11 07 14 72 26 09 01 70 18 8d ?? 00 00 01 25 17 17 8d ?? 00 00 01 25 16 07 a2 a2 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 13 08 11 08 74 ?? 00 00 01 13 09 11 09 } //5
	condition:
		((#a_01_0  & 1)*6+(#a_03_1  & 1)*5) >=11
 
}