
rule Trojan_BAT_AgentTesla_PSVO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSVO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {02 28 0c 00 00 06 75 04 00 00 1b 28 15 00 00 06 2a } //00 00 
	condition:
		any of ($a_*)
 
}