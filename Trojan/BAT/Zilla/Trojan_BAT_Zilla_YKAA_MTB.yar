
rule Trojan_BAT_Zilla_YKAA_MTB{
	meta:
		description = "Trojan:BAT/Zilla.YKAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 04 2b 2a 03 11 04 9a 28 ?? 00 00 0a 20 ?? 03 00 00 da 8c ?? 00 00 01 13 05 08 11 05 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 04 17 d6 13 04 11 04 09 31 d1 08 6f ?? 00 00 0a 0a 2b 00 06 2a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}