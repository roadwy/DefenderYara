
rule Trojan_BAT_DarkTortilla_ROAA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.ROAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 13 06 00 73 ?? 00 00 0a 13 07 00 11 07 11 06 17 73 ?? 00 00 0a 13 08 11 08 02 74 ?? 00 00 1b 16 02 14 72 2d 07 00 70 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 08 6f ?? 00 00 0a 00 de 0e } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}