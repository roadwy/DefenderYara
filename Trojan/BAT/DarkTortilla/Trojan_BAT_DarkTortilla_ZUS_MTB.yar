
rule Trojan_BAT_DarkTortilla_ZUS_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.ZUS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {04 1f 09 5d 2c 03 03 2b 07 03 20 f1 00 00 00 61 b4 0a 2b 00 06 2a } //6
		$a_03_1 = {7a 00 06 7e ?? 00 00 04 2c 07 7e ?? 00 00 04 2b 16 7e ?? 00 00 04 fe 06 69 00 00 06 73 ?? 00 00 0a 25 80 ?? 00 00 04 28 ?? 00 00 2b 28 ?? 00 00 2b 0b } //5
	condition:
		((#a_01_0  & 1)*6+(#a_03_1  & 1)*5) >=11
 
}