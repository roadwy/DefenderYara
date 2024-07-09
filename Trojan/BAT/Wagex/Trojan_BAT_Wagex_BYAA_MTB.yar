
rule Trojan_BAT_Wagex_BYAA_MTB{
	meta:
		description = "Trojan:BAT/Wagex.BYAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 06 0b 28 ?? 00 00 0a 02 6f ?? 00 00 0a 0c 73 ?? 00 00 0a 0d 09 18 6f ?? 00 00 0a 00 73 ?? 00 00 0a 13 04 11 04 09 06 07 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 05 11 05 08 16 08 8e 69 6f ?? 00 00 0a 00 11 05 6f ?? 00 00 0a 00 73 ?? 00 00 0a 13 06 00 11 04 6f ?? 00 00 0a 13 07 16 13 08 2b 23 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}