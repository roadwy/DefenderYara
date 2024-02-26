
rule Trojan_BAT_AgentTesla_RDAE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {6f 25 00 00 0a 13 04 73 26 00 00 0a 13 05 08 73 27 00 00 0a 13 06 11 06 11 04 16 } //00 00 
	condition:
		any of ($a_*)
 
}