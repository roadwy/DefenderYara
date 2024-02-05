
rule Trojan_BAT_AgentTesla_MBDQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBDQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {34 00 44 00 35 00 41 00 39 00 3a 00 3a 00 3a 00 3a 00 33 00 3a 00 3a 00 3a 00 3a 00 3a 00 3a 00 3a 00 34 00 3a 00 3a 00 3a 00 3a 00 3a 00 3a 00 51 00 51 00 51 00 51 00 3a 00 3a 00 3a 00 3a 00 42 00 38 00 } //01 00 
		$a_01_1 = {45 00 31 00 51 00 42 00 41 00 3a 00 45 00 3a 00 3a 00 42 00 34 00 3a 00 39 00 43 00 44 00 32 00 31 00 42 00 38 00 3a 00 31 00 34 00 43 00 43 00 44 00 32 00 31 00 35 00 34 00 36 00 } //00 00 
	condition:
		any of ($a_*)
 
}