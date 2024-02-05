
rule Trojan_BAT_AgentTesla_MBJC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBJC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {4a 00 56 00 4e 00 4a 00 2a 00 41 00 44 00 2a 00 2a 00 41 00 5f 00 2a 00 2a 00 41 00 50 00 37 00 37 00 59 00 2a 00 43 00 34 00 2a 00 2a 00 2a 00 2a 00 2a 00 41 00 43 00 2a 00 2a 00 } //01 00 
		$a_01_1 = {41 00 51 00 2a 00 2a 00 2a 00 4f 00 44 00 36 00 35 00 41 00 34 00 41 00 46 00 55 00 5f 00 48 00 47 00 53 00 44 00 4f 00 41 } //00 00 
	condition:
		any of ($a_*)
 
}