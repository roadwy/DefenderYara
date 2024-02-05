
rule Trojan_BAT_AgentTesla_NPP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NPP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {08 11 07 07 11 07 91 7e 90 01 03 04 11 07 7e 90 01 03 04 6f 90 01 03 0a 5d 6f 90 01 03 0a 28 90 01 03 0a 28 90 01 03 0a 61 9c 11 07 17 d6 13 07 11 07 11 06 31 ca 90 00 } //01 00 
		$a_01_1 = {53 70 6c 69 74 } //00 00 
	condition:
		any of ($a_*)
 
}