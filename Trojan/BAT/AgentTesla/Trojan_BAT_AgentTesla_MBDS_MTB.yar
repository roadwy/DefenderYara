
rule Trojan_BAT_AgentTesla_MBDS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBDS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {34 00 44 00 35 00 41 00 39 00 7d 00 7d 00 7d 00 7d 00 33 00 7d 00 7d 00 7d 00 7d 00 7d 00 7d 00 7d 00 34 00 7d 00 7d 00 7d 00 7d 00 7d 00 7d 00 51 00 51 00 51 00 51 00 7d 00 7d 00 7d 00 7d 00 42 00 38 00 7d 00 7d 00 7d 00 7d 00 } //01 00 
		$a_01_1 = {7d 00 7d 00 35 00 7d 00 34 00 35 00 7d 00 7d 00 7d 00 7d 00 34 00 43 00 7d 00 31 00 7d 00 33 00 7d 00 7d 00 43 00 32 00 38 00 44 00 7d 00 41 00 36 00 34 00 7d 00 7d 00 7d 00 } //00 00 
	condition:
		any of ($a_*)
 
}