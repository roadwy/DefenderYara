
rule Trojan_BAT_AgentTesla_EEC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EEC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 09 06 09 18 5a 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 9c 00 09 17 58 0d 90 00 } //01 00 
		$a_00_1 = {57 00 34 00 2e 00 48 00 63 00 } //01 00 
		$a_01_2 = {00 47 65 74 54 79 70 65 00 } //01 00 
		$a_01_3 = {00 43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 00 } //01 00 
		$a_01_4 = {00 53 75 62 73 74 72 69 6e 67 00 } //01 00 
		$a_01_5 = {00 44 69 73 70 6c 61 79 4e 61 6d 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}