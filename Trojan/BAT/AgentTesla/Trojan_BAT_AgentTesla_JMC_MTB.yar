
rule Trojan_BAT_AgentTesla_JMC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 11 04 06 11 04 18 d8 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a b4 9c 11 04 17 d6 13 04 11 04 09 3e } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}