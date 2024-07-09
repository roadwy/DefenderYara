
rule Trojan_BAT_AgentTesla_AABV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AABV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 05 09 08 6f ?? 00 00 0a 13 0d 16 13 04 11 06 06 9a 20 6d 5f 9d a1 28 ?? 00 00 06 28 ?? 00 00 0a 2c 0b 12 0d 28 ?? 00 00 0a 13 04 2b 3e 11 06 06 9a 20 65 5f 9d a1 28 ?? 00 00 06 28 ?? 00 00 0a 2c 0b 12 0d 28 ?? 00 00 0a 13 04 2b 1e 11 06 06 9a 20 5d 5f 9d a1 28 ?? 00 00 06 28 ?? 00 00 0a 2c 09 12 0d 28 ?? 00 00 0a 13 04 11 07 11 04 6f ?? 00 00 0a 09 17 58 0d 09 11 08 3f } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}