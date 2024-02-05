
rule Trojan_BAT_AgentTesla_Y_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.Y!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {80 05 00 00 04 28 90 01 03 0a 7e 90 01 03 04 28 90 01 03 06 74 90 01 03 1b 80 90 01 03 04 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}