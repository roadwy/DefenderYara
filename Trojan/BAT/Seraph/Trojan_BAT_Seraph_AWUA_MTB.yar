
rule Trojan_BAT_Seraph_AWUA_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AWUA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 04 2b 1f 08 11 04 07 11 04 91 09 11 04 09 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 11 04 17 58 13 04 11 04 07 8e 69 32 da 06 08 6f ?? 00 00 0a 06 16 6f ?? 00 00 0a 13 05 de 03 26 de 93 11 05 2a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}