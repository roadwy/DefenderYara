
rule Trojan_BAT_DarkTortilla_XCAA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.XCAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {04 2c 07 7e ?? 00 00 04 2b 16 7e ?? 00 00 04 fe ?? ?? 00 00 06 73 ?? 00 00 0a 25 80 ?? 00 00 04 28 ?? 00 00 2b 16 28 ?? 00 00 2b 0b 07 14 72 e5 00 00 70 18 8d ?? 00 00 01 25 17 17 8d ?? 00 00 01 25 16 02 a2 a2 14 14 14 28 ?? 00 00 0a 0a de 11 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}