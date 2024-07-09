
rule Trojan_BAT_AgentTesla_EAP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {1a 2c 42 00 2b 10 2b 15 2b 16 2b 1b 2b 1c 2b 21 2b 26 2b 2b de 2f 28 ?? 00 00 06 2b e9 0a 2b e8 28 ?? 00 00 0a 2b e3 06 2b e2 6f ?? 00 00 0a 2b dd 28 ?? 00 00 0a 2b d8 28 ?? 00 00 06 2b d3 0b 2b d2 26 de bb 2b 01 2a 07 2b fc } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}