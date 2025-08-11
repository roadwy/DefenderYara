
rule Trojan_BAT_ResolverRAT_PGR_MTB{
	meta:
		description = "Trojan:BAT/ResolverRAT.PGR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b 1e 2b 3a 2b 3b 2b 3c 08 91 03 08 07 5d 6f ?? 00 00 0a 61 d2 9c 16 2d e9 1a 2c e6 08 17 58 0c 08 02 8e 69 32 dc 06 2a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}