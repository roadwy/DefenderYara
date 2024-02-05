
rule Trojan_BAT_AgentTesla_PSMU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSMU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {02 28 03 00 00 0a 0a 28 04 00 00 0a 06 6f 05 00 00 0a 0b 07 2a } //00 00 
	condition:
		any of ($a_*)
 
}