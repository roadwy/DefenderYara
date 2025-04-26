
rule Trojan_BAT_AgentTesla_PSOF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSOF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {28 40 01 00 0a 02 28 ?? ?? ?? 0a 02 7e 40 00 00 04 20 24 12 00 00 28 37 01 00 06 02 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 02 7b 3a 00 00 04 02 28 42 01 00 0a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}