
rule Trojan_BAT_AgentTesla_NZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 18 13 06 2b 96 06 1f 11 d8 0b 1f 10 8d 90 01 03 01 0c 17 0d 1a 90 00 } //01 00 
		$a_01_1 = {34 39 63 37 61 33 62 66 39 37 33 37 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NZ_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_81_0 = {48 52 48 41 35 34 34 37 45 38 35 4e 56 34 35 35 51 37 37 4f 54 41 78 } //01 00 
		$a_01_1 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00 
		$a_01_2 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NZ_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.NZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {02 03 17 58 90 01 05 5d 91 13 00 90 00 } //01 00 
		$a_01_1 = {57 65 61 74 68 65 72 4f 62 73 65 72 76 65 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } //01 00 
		$a_01_2 = {34 64 33 37 62 38 37 62 64 63 66 39 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NZ_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.NZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {9a 0c 08 19 8d 90 02 04 25 16 7e 90 02 04 a2 25 17 7e 90 02 04 a2 25 18 72 90 02 04 a2 28 90 02 04 26 20 90 02 04 0a 2b 90 09 0e 00 28 90 02 04 0b 07 6f 90 02 04 1f 90 00 } //01 00 
		$a_02_1 = {10 04 02 0e 04 28 90 02 04 28 90 02 04 26 2a 90 09 13 00 28 90 02 05 02 0e 90 01 01 28 90 02 04 28 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}