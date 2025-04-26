
rule Trojan_BAT_DarkTortilla_AALQ_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.AALQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 13 07 07 75 ?? 00 00 1b 11 07 28 ?? 00 00 0a 03 28 ?? 00 00 06 b4 6f ?? 00 00 0a 1e 13 0c 2b 92 08 17 d6 0c ?? 13 0c 2b 89 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}