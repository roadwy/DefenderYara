
rule Trojan_BAT_DarkTortilla_DRAA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.DRAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 03 28 ?? 00 00 0a 28 ?? 00 00 0a d6 13 05 04 50 06 17 8d ?? 00 00 01 25 16 11 05 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 04 17 d6 13 04 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}