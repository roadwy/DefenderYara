
rule Trojan_BAT_AgentTesla_MB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {a2 25 17 7e 90 01 02 00 04 a2 25 18 72 90 01 02 00 70 a2 28 90 01 02 00 0a 26 90 00 } //01 00 
		$a_80_1 = {4d 61 69 6e 57 69 6e 64 6f 77 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //MainWindow.Resources.resources  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_MB_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 05 00 00 03 00 "
		
	strings :
		$a_81_0 = {45 6d 61 69 6c 20 43 68 65 63 6b 65 72 20 50 72 6f } //03 00 
		$a_81_1 = {55 4c 45 73 65 } //03 00 
		$a_81_2 = {64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 } //03 00 
		$a_81_3 = {33 74 67 5f 78 73 67 } //03 00 
		$a_81_4 = {71 66 61 2f 74 69 5f 30 74 69 5f } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_MB_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {16 0d 2b 22 06 09 08 09 08 8e 69 5d 91 07 09 91 61 d2 6f 90 01 03 0a 2b 03 0c 2b e4 09 17 58 0d 2b 04 2c 0f 2b c9 09 07 8e 69 32 02 2b 05 2b d4 0b 2b b9 90 00 } //01 00 
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00 
		$a_01_2 = {47 65 74 42 79 74 65 73 } //01 00 
		$a_01_3 = {54 6f 41 72 72 61 79 } //01 00 
		$a_01_4 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00 
		$a_01_5 = {67 65 74 5f 50 72 6f 63 65 73 73 6f 72 43 6f 75 6e 74 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_MB_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 01 00 "
		
	strings :
		$a_03_0 = {8e 69 1e 5a 6f 90 01 03 0a 00 07 02 7b 90 01 03 04 6f 90 01 03 0a 00 07 02 7b 90 01 03 04 8e 69 1e 5a 6f 90 01 03 0a 00 07 02 7b 90 01 03 04 6f 90 01 03 0a 00 07 6f 90 01 03 0a 0c 00 03 73 90 01 03 0a 0d 00 09 08 16 73 59 01 00 0a 13 04 00 03 8e 69 8d 90 01 01 00 00 01 13 05 11 04 11 05 16 03 8e 69 6f 90 01 03 0a 13 06 11 05 11 06 28 90 01 03 2b 28 90 01 03 2b 0a 00 de 90 00 } //01 00 
		$a_01_1 = {47 65 74 42 79 74 65 73 } //01 00 
		$a_01_2 = {54 6f 53 74 72 69 6e 67 } //01 00 
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00 
		$a_01_4 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //01 00 
		$a_01_5 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00 
		$a_01_6 = {52 65 70 6c 61 63 65 } //01 00 
		$a_01_7 = {67 65 74 5f 4d 6f 75 73 65 4f 76 65 72 42 61 63 6b 67 72 6f 75 6e 64 } //01 00 
		$a_01_8 = {53 65 74 53 74 61 74 65 4d 61 63 68 69 6e 65 } //01 00 
		$a_01_9 = {67 65 74 5f 4b 65 79 } //01 00 
		$a_01_10 = {44 65 62 75 67 } //01 00 
		$a_01_11 = {67 65 74 5f 43 61 70 73 4c 6f 63 6b } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_MB_MTB_5{
	meta:
		description = "Trojan:BAT/AgentTesla.MB!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {01 57 15 a2 09 09 0b 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 31 00 00 00 06 00 00 00 06 00 00 00 0f } //05 00 
		$a_01_1 = {13 05 00 11 04 13 08 16 13 09 2b 15 11 08 11 09 9a 13 0a 11 0a 6f 27 00 00 0a 00 11 09 17 58 13 09 11 09 11 08 8e 69 32 e3 } //00 00 
	condition:
		any of ($a_*)
 
}