
rule Trojan_BAT_AgentTesla_R_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.R!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {b5 13 04 17 0c 2b 25 07 09 02 08 17 28 90 01 04 28 90 01 04 61 28 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_R_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.R!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {01 25 16 28 90 01 03 06 9d 25 17 28 90 01 03 06 9d 25 28 90 01 03 06 73 90 01 03 0a 90 02 40 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}