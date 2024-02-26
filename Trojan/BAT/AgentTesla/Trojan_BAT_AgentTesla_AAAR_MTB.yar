
rule Trojan_BAT_AgentTesla_AAAR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AAAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {11 05 11 02 18 5b 02 11 02 18 6f 90 01 02 00 0a 1f 10 28 90 01 02 00 06 9c 38 90 01 01 00 00 00 16 13 02 38 90 01 01 ff ff ff 11 00 18 5b 8d 90 01 01 00 00 01 13 05 38 90 01 01 ff ff ff 00 11 02 18 58 13 02 38 90 01 01 00 00 00 00 02 6f 90 01 02 00 0a 13 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}