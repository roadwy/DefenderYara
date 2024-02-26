
rule Trojan_BAT_AgentTesla_PTIE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTIE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {6f 1a 00 00 0a 04 0e 08 04 8e 69 6f 1b 00 00 0a 0a 06 0b 2b 00 } //00 00 
	condition:
		any of ($a_*)
 
}