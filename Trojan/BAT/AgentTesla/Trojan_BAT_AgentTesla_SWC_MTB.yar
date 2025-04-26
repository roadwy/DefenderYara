
rule Trojan_BAT_AgentTesla_SWC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SWC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 14 7d 05 00 00 04 02 28 36 00 00 0a 00 00 28 0d 00 00 06 74 03 00 00 01 28 37 00 00 0a 26 02 28 27 00 00 06 00 2a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}