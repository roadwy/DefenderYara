
rule Trojan_BAT_DarkTortilla_DDAA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.DDAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 07 72 7e 35 00 70 17 8d ?? 00 00 01 25 16 d0 ?? 00 00 1b 28 ?? 00 00 0a a2 6f ?? 00 00 0a 0c 08 14 17 8d ?? 00 00 01 25 16 02 a2 6f ?? 00 00 0a 28 ?? 00 00 0a 0d 09 0a de 12 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}