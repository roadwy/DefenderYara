
rule Trojan_BAT_AgentTesla_AP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {01 25 16 7e 90 01 03 04 a2 25 17 7e 90 01 03 04 a2 25 18 20 90 01 04 28 90 01 03 06 a2 73 90 01 03 06 7d 90 01 03 04 02 28 90 01 03 0a 02 16 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_AP_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {19 9a 20 5b 10 00 00 95 e0 95 7e 29 00 00 04 19 9a 20 59 0e 00 00 95 61 7e 29 00 00 04 19 9a 20 1c 03 00 00 95 2e 03 17 2b 01 16 } //02 00 
		$a_01_1 = {19 9a 20 42 11 00 00 95 5f 7e 29 00 00 04 19 9a 1f 7d 95 61 61 80 27 00 00 04 2b 72 7e 27 00 00 04 7e 29 00 00 04 19 9a 20 5f 06 00 00 95 33 44 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_AP_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.AP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {0d 16 13 05 2b 15 09 11 05 08 11 05 91 20 89 00 00 00 61 d2 9c 11 05 17 58 13 05 11 05 08 8e 69 17 59 } //01 00 
		$a_01_1 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 45 00 64 00 67 00 65 00 46 00 73 00 73 00 5c 00 46 00 69 00 6c 00 65 00 53 00 79 00 6e 00 63 00 53 00 68 00 65 00 6c 00 6c 00 36 00 34 00 2e 00 64 00 61 00 74 00 } //01 00 
		$a_01_2 = {47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 } //01 00 
		$a_01_3 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //00 00 
	condition:
		any of ($a_*)
 
}