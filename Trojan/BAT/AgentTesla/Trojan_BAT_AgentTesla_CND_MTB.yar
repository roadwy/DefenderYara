
rule Trojan_BAT_AgentTesla_CND_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_01_0 = {11 06 11 05 08 28 4a 00 00 06 13 07 09 28 4b 00 00 06 13 08 11 08 11 07 16 28 4c 00 00 06 13 09 } //01 00 
		$a_01_1 = {50 61 73 73 47 65 6e } //01 00 
		$a_01_2 = {4d 75 74 65 78 } //00 00 
	condition:
		any of ($a_*)
 
}