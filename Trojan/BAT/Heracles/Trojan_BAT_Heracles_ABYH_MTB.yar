
rule Trojan_BAT_Heracles_ABYH_MTB{
	meta:
		description = "Trojan:BAT/Heracles.ABYH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 06 16 73 ?? 00 00 0a 73 ?? 00 00 0a 0c 08 07 6f ?? 00 00 0a 07 6f ?? 00 00 0a 28 ?? 00 00 2b 28 ?? 00 00 2b 28 ?? 00 00 0a 72 ?? 00 00 70 6f ?? 00 00 0a 0d d0 ?? 00 00 01 28 ?? 00 00 0a 09 72 ?? 00 00 70 28 ?? 00 00 0a 16 8d ?? 00 00 01 6f ?? 00 00 0a 26 de 1e 08 2c 06 08 6f ?? 00 00 0a dc } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}