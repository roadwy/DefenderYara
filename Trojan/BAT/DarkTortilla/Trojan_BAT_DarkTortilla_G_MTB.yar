
rule Trojan_BAT_DarkTortilla_G_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 00 01 25 16 11 05 a2 14 28 ?? 00 00 0a 28 ?? 00 00 0a 16 16 11 09 11 08 18 28 ?? 02 00 06 28 ?? 00 00 0a 18 28 ?? 02 00 06 28 ?? 00 00 0a 8c ?? 00 00 01 a2 14 28 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}