
rule Trojan_BAT_DarkTortilla_ZBI_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.ZBI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 07 07 11 07 28 ?? 02 00 0a 03 28 ?? 04 00 06 b4 6f ?? 02 00 0a 00 00 11 06 6f ?? 00 00 0a 13 08 11 08 2d cf } //6
		$a_01_1 = {02 03 61 0b 07 0a 2b 00 06 2a } //5 ̂ୡਇ+⨆
	condition:
		((#a_03_0  & 1)*6+(#a_01_1  & 1)*5) >=11
 
}