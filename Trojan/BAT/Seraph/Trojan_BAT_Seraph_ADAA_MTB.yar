
rule Trojan_BAT_Seraph_ADAA_MTB{
	meta:
		description = "Trojan:BAT/Seraph.ADAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 2b 2e 16 2b 2e 2b 33 2b 38 16 2d 09 2b 09 2b 0a 6f ?? 00 00 0a de 10 08 2b f4 07 2b f3 08 2c 06 08 6f ?? 00 00 0a dc 07 6f ?? 00 00 0a 0d de 2e 06 2b cf 73 ?? 00 00 0a 2b cb 73 ?? 00 00 0a 2b c6 0c 2b c5 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}