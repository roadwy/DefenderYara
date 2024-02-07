
rule Trojan_BAT_AgentTesla_ASCO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASCO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 06 8e 69 17 da 13 1f 16 13 20 2b 1a 11 07 11 06 11 20 9a 1f 10 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 00 11 20 17 d6 13 20 11 20 11 1f 31 e0 90 00 } //01 00 
		$a_81_1 = {46 69 6e 61 6c 5f 50 72 6f 6a 65 63 74 2e 52 65 73 6f 75 72 63 65 73 } //00 00  Final_Project.Resources
	condition:
		any of ($a_*)
 
}