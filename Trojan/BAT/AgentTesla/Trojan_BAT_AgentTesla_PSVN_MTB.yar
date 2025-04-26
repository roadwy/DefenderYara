
rule Trojan_BAT_AgentTesla_PSVN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSVN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 28 0c 00 00 06 75 16 00 00 01 28 ?? 00 00 06 28 ?? 00 00 2b 2a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}