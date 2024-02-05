
rule Trojan_BAT_AgentTesla_UG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.UG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {5f 0c 11 04 07 e0 95 0d 11 04 07 e0 11 04 08 e0 95 9e 11 04 08 e0 09 9e 11 05 11 06 d4 02 11 06 d4 91 11 04 11 04 07 e0 95 11 04 08 e0 95 58 20 90 02 04 5f e0 95 61 28 90 02 04 9c 11 06 17 6a 58 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}