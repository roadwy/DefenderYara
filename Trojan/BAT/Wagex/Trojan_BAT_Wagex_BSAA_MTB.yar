
rule Trojan_BAT_Wagex_BSAA_MTB{
	meta:
		description = "Trojan:BAT/Wagex.BSAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 08 06 6f ?? 00 00 0a 08 07 6f ?? 00 00 0a 08 17 6f ?? 00 00 0a 08 08 6f ?? 00 00 0a 08 6f ?? 00 00 0a 6f ?? 00 00 0a 0d 02 73 ?? 00 00 0a 13 04 11 04 09 17 73 ?? 00 00 0a 13 05 11 05 02 16 02 8e 69 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 13 06 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}