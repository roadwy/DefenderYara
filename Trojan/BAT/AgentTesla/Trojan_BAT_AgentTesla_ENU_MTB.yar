
rule Trojan_BAT_AgentTesla_ENU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ENU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {02 09 95 28 90 01 03 0a 13 04 11 04 8e 69 17 da 13 05 16 13 06 2b 13 07 09 1a d8 11 06 d6 11 04 11 06 91 9c 11 06 17 d6 13 06 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}