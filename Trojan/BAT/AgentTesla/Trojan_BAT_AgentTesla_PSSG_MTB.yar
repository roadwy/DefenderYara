
rule Trojan_BAT_AgentTesla_PSSG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSSG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {00 00 0a 02 72 0d 00 00 70 28 09 00 00 06 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 28 90 01 01 00 00 06 0a dd 06 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}