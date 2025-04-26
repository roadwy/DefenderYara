
rule Trojan_BAT_AgentTesla_PTEM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTEM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {7e 2a 01 00 04 28 ?? 01 00 06 11 26 7e 2a 01 00 04 28 ?? 01 00 06 7e 88 01 00 04 28 ?? 02 00 06 28 ?? 00 00 2b 13 15 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}