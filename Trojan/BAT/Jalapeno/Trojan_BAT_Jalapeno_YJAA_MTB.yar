
rule Trojan_BAT_Jalapeno_YJAA_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.YJAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 05 11 04 1f 10 6f ?? 01 00 0a 6f ?? 01 00 0a 00 11 05 11 05 6f ?? 01 00 0a 11 05 6f ?? 01 00 0a 6f ?? 01 00 0a 13 06 11 06 02 74 ?? 00 00 1b 16 02 14 72 1e 2c 00 70 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 01 00 0a 0b 07 74 ?? 00 00 1b 28 ?? 01 00 06 14 72 44 2c 00 70 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a 74 ?? 00 00 1b 0a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}