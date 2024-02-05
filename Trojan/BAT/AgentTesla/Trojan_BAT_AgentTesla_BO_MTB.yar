
rule Trojan_BAT_AgentTesla_BO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {0a 0b 07 06 1f 10 6f 90 01 04 6f 90 01 04 07 06 1f 10 6f 90 01 04 6f 90 01 04 07 6f 90 01 04 02 16 02 8e 69 6f 90 01 04 0c 08 8e 69 1f 11 da 17 d6 17 da 17 d6 8d 90 01 04 0d 08 1f 10 09 16 08 8e 69 1f 10 da 28 90 01 04 09 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}