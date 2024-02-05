
rule Trojan_BAT_AgentTesla_RPK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RPK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {17 59 7e 28 00 00 04 11 07 13 0a 18 9a 20 a0 0d 00 00 11 0d 13 07 95 5f 7e 28 00 00 04 18 9a 20 de 07 00 00 95 61 59 81 06 00 00 01 38 76 07 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_RPK_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.RPK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {09 17 8d 6c 00 00 01 25 16 08 17 8d 17 00 00 01 25 16 11 04 8c 59 00 00 01 a2 14 28 a8 00 00 0a 28 87 00 00 0a 1f 10 28 ae 00 00 0a 9c 6f af 00 00 0a 00 11 04 17 d6 13 04 00 11 04 20 00 7c 00 00 fe 04 13 06 11 06 2d b7 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_RPK_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.RPK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {11 07 11 0a 11 06 11 0a 9a 1f 10 28 4f 01 00 0a d2 9c 11 0a 17 58 13 0a 11 0a 11 06 8e 69 fe 04 13 0b 11 0b 2d da } //01 00 
		$a_01_1 = {4d 00 65 00 6c 00 76 00 69 00 6e 00 2e 00 57 00 68 00 69 00 74 00 65 00 } //01 00 
		$a_01_2 = {41 00 6d 00 69 00 72 00 43 00 61 00 6c 00 65 00 6e 00 64 00 61 00 72 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_RPK_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.RPK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {72 00 61 00 64 00 69 00 6f 00 2d 00 68 00 69 00 74 00 2e 00 72 00 6f 00 2f 00 47 00 6e 00 63 00 6e 00 66 00 2e 00 70 00 6e 00 67 } //01 00 
		$a_01_1 = {57 65 62 52 65 71 75 65 73 74 } //01 00 
		$a_01_2 = {47 65 74 52 65 73 70 6f 6e 73 65 } //01 00 
		$a_01_3 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //01 00 
		$a_01_4 = {52 65 61 64 42 79 74 65 73 } //01 00 
		$a_01_5 = {42 69 6e 61 72 79 52 65 61 64 65 72 } //01 00 
		$a_01_6 = {52 65 76 65 72 73 65 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_RPK_MTB_5{
	meta:
		description = "Trojan:BAT/AgentTesla.RPK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 } //01 00 
		$a_01_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //01 00 
		$a_01_2 = {2d 00 65 00 6e 00 63 00 20 00 59 00 77 00 42 00 74 00 41 00 47 00 51 00 41 00 49 00 41 00 41 00 76 00 41 00 47 00 4d 00 41 00 49 00 41 00 42 00 30 00 41 00 47 00 6b 00 41 00 62 00 51 00 42 00 6c 00 41 00 47 00 38 00 41 00 64 00 51 00 42 00 30 00 41 00 43 00 41 00 41 00 4d 00 67 00 41 00 77 00 41 00 41 00 } //01 00 
		$a_01_3 = {42 00 61 00 6e 00 6b 00 5f 00 52 00 65 00 70 00 6f 00 72 00 74 00 5f 00 30 00 30 00 30 00 32 00 32 00 35 00 2e 00 6a 00 70 00 67 00 } //01 00 
		$a_01_4 = {50 00 71 00 73 00 6b 00 6a 00 67 00 62 00 70 00 61 00 67 00 72 00 } //00 00 
	condition:
		any of ($a_*)
 
}