
rule Trojan_BAT_AgentTesla_ABTO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABTO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 08 16 07 16 1f 10 28 ?? 00 00 0a 08 16 07 1f 0f 1f 10 28 ?? 00 00 0a 06 07 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 06 6f ?? 00 00 0a 0d 09 03 16 03 8e 69 6f ?? 00 00 0a 2a 73 ?? 00 00 0a 2b a0 0a 2b 9f 0b 2b a5 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}