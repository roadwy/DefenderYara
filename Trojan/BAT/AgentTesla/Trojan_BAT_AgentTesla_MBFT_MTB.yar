
rule Trojan_BAT_AgentTesla_MBFT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBFT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {11 09 2a 00 02 11 04 91 11 01 61 11 00 11 03 91 61 13 0a } //00 00 
	condition:
		any of ($a_*)
 
}