
rule Trojan_BAT_AgentTesla_SSPP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SSPP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {13 04 09 73 90 01 03 0a 13 05 11 05 08 16 73 90 01 03 0a 13 06 11 06 11 04 6f 90 01 03 0a 11 04 6f 90 01 03 0a 0a de 2e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}