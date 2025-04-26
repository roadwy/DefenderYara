
rule Trojan_BAT_HiveMon_AAPJ_MTB{
	meta:
		description = "Trojan:BAT/HiveMon.AAPJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 0c 72 01 00 00 70 6f ?? 00 00 0a 28 ?? 00 00 06 28 ?? 00 00 0a 28 ?? 00 00 0a 13 0d 11 0c 72 49 00 00 70 72 a1 00 00 70 72 c1 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 06 28 ?? 00 00 0a 28 ?? 00 00 0a 13 0e 11 0e 28 ?? 00 00 0a 13 0f 11 0f 72 d1 00 00 70 72 a1 00 00 70 72 1b 01 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 72 1f 01 00 70 72 a1 00 00 70 72 43 01 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 13 10 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}