
rule Trojan_BAT_AsyncRAT_SKHP_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.SKHP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 07 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 07 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 07 6f ?? 00 00 0a 06 16 06 8e 69 6f ?? 00 00 0a 0a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}