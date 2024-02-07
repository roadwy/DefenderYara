
rule Trojan_BAT_AgentTesla_FT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.FT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_00_0 = {02 50 08 02 50 8e 69 6a 5d b7 02 50 08 02 50 8e 69 6a 5d b7 91 03 08 03 8e 69 6a 5d b7 91 61 02 50 08 17 6a d6 02 50 8e 69 6a 5d b7 91 da 20 00 01 00 00 d6 20 00 01 00 00 5d b4 9c 08 17 6a d6 0c 08 07 31 bb } //01 00 
		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_3 = {41 63 74 69 76 61 74 6f 72 } //00 00  Activator
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_FT_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.FT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 0b 00 00 14 00 "
		
	strings :
		$a_01_0 = {24 30 37 39 46 39 45 36 31 2d 31 35 34 46 2d 34 30 42 41 2d 41 44 41 41 2d 35 33 35 37 34 35 46 43 35 44 43 30 } //14 00  $079F9E61-154F-40BA-ADAA-535745FC5DC0
		$a_81_1 = {24 39 35 37 62 62 37 64 32 2d 31 35 38 35 2d 34 31 61 30 2d 38 30 61 32 2d 65 65 33 63 62 62 65 36 33 34 31 35 } //14 00  $957bb7d2-1585-41a0-80a2-ee3cbbe63415
		$a_81_2 = {24 36 35 33 31 31 39 65 65 2d 66 30 39 34 2d 34 34 39 63 2d 39 36 63 30 2d 39 63 35 64 38 30 38 32 64 63 37 35 } //14 00  $653119ee-f094-449c-96c0-9c5d8082dc75
		$a_81_3 = {24 39 35 66 34 36 32 31 63 2d 62 33 34 31 2d 34 63 66 66 2d 62 63 34 64 2d 34 65 32 30 36 31 30 36 66 30 33 37 } //14 00  $95f4621c-b341-4cff-bc4d-4e206106f037
		$a_81_4 = {24 66 34 31 37 33 66 61 65 2d 64 39 62 38 2d 34 61 63 32 2d 62 31 63 61 2d 34 33 36 36 65 37 61 63 39 34 30 38 } //01 00  $f4173fae-d9b8-4ac2-b1ca-4366e7ac9408
		$a_81_5 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_81_6 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_81_7 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //01 00  DebuggingModes
		$a_81_8 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_9 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_10 = {41 63 74 69 76 61 74 6f 72 } //00 00  Activator
	condition:
		any of ($a_*)
 
}