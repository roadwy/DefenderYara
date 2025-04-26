
rule Trojan_BAT_AgentTesla_ABZR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABZR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 1f 10 28 ?? 00 00 06 6f ?? 00 00 0a 0a 02 28 ?? 00 00 0a 0b 73 ?? 00 00 0a 0c 08 06 6f ?? 00 00 0a 08 18 6f ?? 00 00 0a 08 17 6f ?? 00 00 0a 08 6f ?? 00 00 0a 0d 09 07 16 07 8e 69 6f ?? 00 00 0a 13 04 28 ?? 00 00 0a 11 04 6f ?? 00 00 0a 13 05 11 05 17 8d ?? 00 00 01 13 06 11 06 6f ?? 00 00 0a 2a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}