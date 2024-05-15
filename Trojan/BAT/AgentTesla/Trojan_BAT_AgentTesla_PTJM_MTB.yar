
rule Trojan_BAT_AgentTesla_PTJM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTJM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {00 7e 03 00 00 04 6f 31 00 00 0a 05 0e 07 0e 04 8e 69 6f 32 00 00 0a 0a 06 0b 2b 00 07 2a } //00 00 
	condition:
		any of ($a_*)
 
}