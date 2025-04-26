
rule Trojan_BAT_DarkTortilla_AAMV_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.AAMV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 13 04 07 11 04 1c 8c ?? 00 00 01 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 19 13 09 2b 98 00 08 17 d6 0c 00 ?? 13 09 2b 8d } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}