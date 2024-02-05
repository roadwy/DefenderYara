
rule Trojan_BAT_AgentTesla_SQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {03 50 09 03 50 8e 69 6a 5d b7 03 50 09 03 50 8e 69 6a 5d b7 91 07 09 07 8e 69 6a 5d b7 91 61 03 50 09 17 6a d6 03 50 8e 69 6a 5d b7 91 da 20 90 01 04 d6 20 90 01 04 5d b4 9c 09 17 6a d6 0d 09 08 31 bb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}