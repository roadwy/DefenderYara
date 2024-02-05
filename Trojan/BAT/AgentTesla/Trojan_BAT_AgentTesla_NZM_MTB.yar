
rule Trojan_BAT_AgentTesla_NZM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NZM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {02 11 04 91 11 01 61 11 00 11 03 91 61 13 09 } //01 00 
		$a_01_1 = {39 63 38 64 37 63 66 65 65 65 64 61 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NZM_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NZM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 00 69 00 65 00 73 00 2e 00 57 00 68 00 69 00 74 00 65 00 } //01 00 
		$a_01_1 = {53 70 6c 69 74 } //01 00 
		$a_01_2 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00 
		$a_01_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00 
		$a_01_4 = {47 65 74 54 79 70 65 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NZM_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.NZM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {24 64 39 63 32 30 66 38 30 2d 38 31 38 61 2d 34 61 30 35 2d 62 63 62 36 2d 63 37 39 36 61 62 32 38 36 34 30 39 } //01 00 
		$a_01_1 = {47 65 74 54 79 70 65 73 } //01 00 
		$a_01_2 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00 
		$a_01_3 = {47 65 74 4d 65 74 68 6f 64 73 } //01 00 
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00 
	condition:
		any of ($a_*)
 
}