
rule Trojan_BAT_AgentTesla_NA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {72 7c 3b 02 70 17 8d 90 01 03 01 25 16 11 01 a2 25 13 02 90 00 } //01 00 
		$a_01_1 = {51 00 51 00 51 00 57 00 57 00 57 00 } //01 00 
		$a_01_2 = {62 00 6c 00 6e 00 41 00 6f 00 79 00 58 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NA_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {06 07 6f 2c 00 00 0a 0c 20 90 01 03 ff 28 90 01 03 0a fe 90 01 02 00 38 90 01 03 00 90 00 } //01 00 
		$a_01_1 = {70 75 62 6c 69 63 2e 63 6c 61 73 73 2e 4d 61 69 6e 2e 48 65 6c 6c 6f 57 6f 72 6c 64 2e 6d 6f 64 75 6c 65 31 33 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NA_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {8f 0b 00 00 01 25 71 90 01 01 00 00 01 fe 90 01 02 00 fe 90 01 02 00 20 90 01 01 00 00 00 5d 91 61 d2 81 90 01 01 00 00 01 20 90 01 01 00 00 00 fe 90 01 02 00 00 fe 90 01 02 00 20 90 01 01 00 00 00 fe 01 39 90 01 01 00 00 00 90 00 } //01 00 
		$a_01_1 = {46 6c 61 6d 65 41 73 73 65 6d 62 6c 69 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NA_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {73 40 00 00 0a 0a 28 90 01 01 00 00 06 0b 07 1f 20 8d 90 01 01 00 00 01 25 d0 90 01 01 00 00 04 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 07 1f 10 8d 90 01 01 00 00 01 25 d0 90 01 01 00 00 04 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 06 07 6f 90 01 01 00 00 0a 17 73 90 01 01 00 00 0a 0c 08 02 16 02 8e 69 6f 90 01 01 00 00 0a 90 00 } //01 00 
		$a_01_1 = {43 68 75 61 6e 67 2e 50 72 69 6e 74 65 72 2e 43 6c 69 65 6e 74 55 6e 69 6e 73 74 61 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NA_MTB_5{
	meta:
		description = "Trojan:BAT/AgentTesla.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 09 00 00 05 00 "
		
	strings :
		$a_81_0 = {44 65 6c 6f 32 4d 61 69 6c 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //05 00 
		$a_81_1 = {44 65 6c 6f 32 4d 61 69 6c 2e 42 61 69 64 75 } //05 00 
		$a_81_2 = {67 65 74 5f 53 4d 54 50 50 61 73 73 77 6f 72 64 } //01 00 
		$a_81_3 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //01 00 
		$a_81_4 = {41 74 74 61 63 68 6d 65 6e 74 46 69 6c 65 } //01 00 
		$a_81_5 = {53 68 65 6c 6c 45 78 65 63 75 74 65 } //01 00 
		$a_81_6 = {52 53 45 64 69 74 50 61 72 61 6d 65 74 65 72 73 5f 4c 6f 61 64 } //01 00 
		$a_81_7 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00 
		$a_81_8 = {49 43 72 65 64 65 6e 74 69 61 6c 73 42 79 48 6f 73 74 } //00 00 
	condition:
		any of ($a_*)
 
}