
rule Trojan_BAT_DarkTortilla_GEAA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.GEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 00 11 04 18 6f ?? 00 00 0a 00 11 04 6f ?? 00 00 0a 13 05 00 73 ?? 00 00 0a 13 06 00 11 06 11 05 17 73 ?? 00 00 0a 13 07 11 07 02 16 02 8e 69 6f ?? 00 00 0a 00 de 0e } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}