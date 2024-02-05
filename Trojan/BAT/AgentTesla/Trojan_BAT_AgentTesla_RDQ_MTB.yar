
rule Trojan_BAT_AgentTesla_RDQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {04 8e 69 5d 04 08 04 8e 69 5d 91 07 08 07 8e 69 5d 91 61 } //00 00 
	condition:
		any of ($a_*)
 
}