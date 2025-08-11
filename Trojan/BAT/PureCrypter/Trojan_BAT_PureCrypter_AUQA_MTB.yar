
rule Trojan_BAT_PureCrypter_AUQA_MTB{
	meta:
		description = "Trojan:BAT/PureCrypter.AUQA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {1a 25 2c 11 8d ?? 00 00 01 0b 06 07 16 07 8e 69 6f ?? 00 00 0a 26 16 2d f1 07 16 28 ?? 00 00 0a 0c 06 16 73 ?? 00 00 0a 0d 2b 2e 8d ?? 00 00 01 2b 2a 16 2b 2b 1a 2c 02 2b 14 2b 28 2b 2a 2b 2b 11 05 08 11 05 59 6f ?? 00 00 0a 58 13 05 11 05 08 32 e7 11 04 13 06 de 2d 08 2b cf 13 04 2b d2 13 05 2b d1 11 05 2b d4 09 2b d3 11 04 2b d1 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}