
rule Trojan_BAT_AgentTesla_AAJI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AAJI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0d 07 09 1f 37 8c ?? 00 00 01 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 08 6f ?? 00 00 0a 13 04 11 04 2d ce de 15 08 75 ?? 00 00 01 2c 0c 08 75 ?? 00 00 01 6f ?? 00 00 0a 00 dc 07 6f ?? 00 00 0a 28 ?? 00 00 06 74 ?? 00 00 1b 0a 2b 00 06 2a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}