
rule Trojan_BAT_AgentTesla_MBAG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {34 00 44 00 4f 00 35 00 41 00 4f 00 39 00 21 00 4f 00 21 00 21 00 4f 00 21 00 33 00 4f 00 2b 00 21 00 21 00 4f 00 21 00 34 00 4f 00 2b 00 21 00 21 00 4f 00 46 00 46 00 4f 00 46 00 46 00 4f 00 2b 00 42 00 38 00 4f 00 2b 00 2b 00 2b 00 } //01 00  4DO5AO9!O!!O!3O+!!O!4O+!!OFFOFFO+B8O+++
		$a_81_1 = {43 4c 43 30 33 } //01 00  CLC03
		$a_81_2 = {4b 30 30 30 30 32 } //01 00  K00002
		$a_81_3 = {53 79 73 74 65 6d 2e 43 6f 6e 76 65 72 74 } //00 00  System.Convert
	condition:
		any of ($a_*)
 
}