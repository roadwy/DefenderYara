
rule Trojan_BAT_DarkTortilla_AMZA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.AMZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 13 06 11 06 11 04 6f ?? 01 00 0a 00 11 06 11 05 6f ?? 01 00 0a 00 11 06 11 06 6f ?? 01 00 0a 11 06 6f ?? 01 00 0a 6f ?? 01 00 0a 13 07 00 73 ?? 00 00 0a 13 08 00 11 08 11 07 17 73 ?? 01 00 0a 13 09 11 09 02 16 02 8e 69 6f ?? 01 00 0a 00 11 09 6f ?? 01 00 0a 00 11 08 6f ?? 00 00 0a 0a de 2a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}