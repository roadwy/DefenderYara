
rule Trojan_BAT_DarkTortilla_ZJW_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.ZJW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {04 1f 09 5d 2c 03 03 2b 07 03 20 ed 00 00 00 61 b4 0a 2b 00 06 2a } //6
		$a_03_1 = {11 08 14 72 d3 71 00 70 18 8d ?? 00 00 01 25 17 17 8d ?? 00 00 01 25 16 07 a2 a2 14 14 14 28 ?? 01 00 0a 28 ?? 00 00 0a 13 09 11 09 6f ?? 02 00 0a 72 e1 71 00 70 6f ?? 02 00 0a 13 0a } //5
	condition:
		((#a_01_0  & 1)*6+(#a_03_1  & 1)*5) >=11
 
}