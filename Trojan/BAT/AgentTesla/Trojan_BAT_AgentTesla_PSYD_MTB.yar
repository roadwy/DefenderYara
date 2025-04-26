
rule Trojan_BAT_AgentTesla_PSYD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSYD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {6f 85 00 00 0a 11 07 1e d6 13 07 11 07 11 0b 3e 75 ff ff ff 73 88 00 00 0a 0d 09 07 6f ?? 00 00 0a 6f ?? 00 00 0a 2a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}