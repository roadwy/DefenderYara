
rule Trojan_BAT_AgentTesla_PSSK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 28 05 00 00 0a 0a 28 06 00 00 0a 06 28 05 00 00 06 6f 07 00 00 0a 2a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}