
rule Trojan_BAT_AgentTesla_MU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 03 00 "
		
	strings :
		$a_81_0 = {6e 6f 69 74 61 6c 73 6e 61 72 54 } //03 00 
		$a_81_1 = {4f 46 4e 49 5f 4e 4f 49 53 52 45 56 5f 53 56 } //03 00 
		$a_81_2 = {56 53 5f 56 45 52 53 49 4f 4e 5f 49 4e 46 4f } //03 00 
		$a_81_3 = {53 79 73 74 65 6d 2e 43 6f 64 65 44 6f 6d 2e 43 6f 6d 70 69 6c 65 72 } //03 00 
		$a_81_4 = {52 65 76 65 72 73 65 } //03 00 
		$a_81_5 = {39 37 2e 30 2e 31 2e 38 30 38 32 } //00 00 
	condition:
		any of ($a_*)
 
}