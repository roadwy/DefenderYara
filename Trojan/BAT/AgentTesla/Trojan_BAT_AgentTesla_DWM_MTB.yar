
rule Trojan_BAT_AgentTesla_DWM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DWM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 02 08 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 84 28 90 01 03 0a 6f 90 01 03 0a 26 90 00 } //01 00 
		$a_03_1 = {08 11 04 02 11 04 91 07 61 06 09 91 61 28 90 01 03 0a 9c 16 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_DWM_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.DWM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {02 08 18 28 90 01 03 06 1f 10 28 90 01 03 06 84 28 90 01 03 06 28 90 01 03 06 26 90 00 } //01 00 
		$a_03_1 = {08 11 04 7e 90 01 03 04 02 11 04 91 07 61 06 09 91 61 28 90 01 03 06 9c 09 16 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}