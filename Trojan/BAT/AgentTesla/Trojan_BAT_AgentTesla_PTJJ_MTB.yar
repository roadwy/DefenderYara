
rule Trojan_BAT_AgentTesla_PTJJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTJJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {6f 05 00 00 0a 07 16 6a 6f 06 00 00 0a 14 0a 07 6f 07 00 00 0a 28 90 01 01 00 00 0a 0c 08 14 28 90 01 01 00 00 0a 39 2b 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}