
rule Trojan_BAT_AgentTesla_MOC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MOC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {0a 06 16 28 90 01 09 a2 06 28 90 01 0e 2a 90 09 15 00 d0 90 01 0e 17 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}