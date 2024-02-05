
rule Trojan_BAT_AgentTesla_SR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {03 50 08 03 50 8e 69 6a 5d b7 03 50 08 03 50 8e 69 6a 5d b7 91 06 08 06 8e 69 6a 5d b7 91 61 03 50 08 17 6a d6 03 50 8e 69 6a 5d b7 91 da 20 90 01 04 d6 20 90 01 04 5d b4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}