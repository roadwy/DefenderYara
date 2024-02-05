
rule Trojan_BAT_AgentTesla_PM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {0a 02 06 74 90 01 09 06 74 90 02 0e 25 2d 17 26 7e 90 02 0f 25 90 02 0f 25 2d 17 26 7e 90 02 0f 25 90 02 0f 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}