
rule Trojan_BAT_AgentTesla_JRC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JRC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 01 00 "
		
	strings :
		$a_81_0 = {24 33 37 33 65 39 32 30 33 2d 65 30 30 64 2d 34 65 32 66 2d 61 37 32 36 2d 38 65 65 61 65 39 36 61 65 35 37 66 } //01 00  $373e9203-e00d-4e2f-a726-8eeae96ae57f
		$a_81_1 = {00 58 30 46 54 5f 46 54 32 00 } //01 00  堀䘰彔呆2
		$a_81_2 = {00 58 30 46 54 5f 46 54 31 00 } //01 00  堀䘰彔呆1
		$a_81_3 = {74 6f 77 65 72 44 65 66 65 6e 73 65 47 } //01 00  towerDefenseG
		$a_81_4 = {53 75 62 73 74 72 69 6e 67 } //01 00  Substring
		$a_81_5 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_6 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //01 00  GetTypeFromHandle
		$a_81_7 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_81_8 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //01 00  DebuggingModes
		$a_81_9 = {50 61 72 61 6d 58 47 72 6f 75 70 } //01 00  ParamXGroup
		$a_81_10 = {50 61 72 61 6d 58 41 72 72 61 79 } //00 00  ParamXArray
	condition:
		any of ($a_*)
 
}