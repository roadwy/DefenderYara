
rule Trojan_BAT_AgentTesla_PTHE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {6f 0f 00 00 0a dc 06 28 90 01 01 00 00 2b 28 90 01 01 00 00 2b 0a 28 90 01 01 01 00 0a 06 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}