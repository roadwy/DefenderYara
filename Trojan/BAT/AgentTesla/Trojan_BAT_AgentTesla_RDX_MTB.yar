
rule Trojan_BAT_AgentTesla_RDX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {02 28 17 00 00 0a 03 04 05 6f 1d 00 00 0a 28 11 00 00 0a 51 } //00 00 
	condition:
		any of ($a_*)
 
}