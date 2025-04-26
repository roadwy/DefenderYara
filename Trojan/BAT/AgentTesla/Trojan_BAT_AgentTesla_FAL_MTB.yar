
rule Trojan_BAT_AgentTesla_FAL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.FAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 09 08 16 73 ?? 00 00 0a 13 04 00 02 8e 69 8d ?? 00 00 01 13 05 11 04 11 05 16 11 05 8e 69 6f ?? 00 00 0a 13 06 11 05 11 06 28 ?? 00 00 2b 28 ?? 00 00 2b 13 07 de 2e 11 04 2c 08 11 04 6f ?? 00 00 0a 00 dc } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}