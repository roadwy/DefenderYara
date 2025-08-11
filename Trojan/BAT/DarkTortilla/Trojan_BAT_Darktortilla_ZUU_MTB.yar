
rule Trojan_BAT_Darktortilla_ZUU_MTB{
	meta:
		description = "Trojan:BAT/Darktortilla.ZUU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {0c 00 08 07 28 ?? 01 00 06 0d 09 02 28 ?? 01 00 06 00 08 6f ?? 00 00 0a 0a de 24 00 09 2c 07 09 6f ?? 00 00 0a 00 dc 00 08 2c 07 08 } //6
		$a_03_1 = {a2 02 03 17 da 9a 28 ?? 00 00 0a 28 ?? 00 00 06 0a 02 03 1c da 06 a2 02 03 1d da 06 6f ?? 01 00 0a 1f 18 9a a2 02 03 1d da 9a } //5
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*5) >=11
 
}