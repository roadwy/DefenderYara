
rule Trojan_BAT_AgentTesla_MV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 05 00 00 03 00 "
		
	strings :
		$a_00_0 = {57 15 a2 01 09 01 00 00 00 00 00 00 00 00 00 00 01 00 00 00 36 00 00 00 06 } //03 00 
		$a_81_1 = {53 65 63 75 72 69 74 79 50 72 6f 74 6f 63 6f 6c 54 79 70 65 } //03 00  SecurityProtocolType
		$a_81_2 = {53 65 72 76 69 63 65 50 6f 69 6e 74 4d 61 6e 61 67 65 72 } //03 00  ServicePointManager
		$a_81_3 = {73 65 74 5f 53 65 63 75 72 69 74 79 50 72 6f 74 6f 63 6f 6c } //03 00  set_SecurityProtocol
		$a_81_4 = {35 34 2e 36 35 2e 31 33 2e 39 31 } //00 00  54.65.13.91
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_MV_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.MV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_03_0 = {0b 1f 25 28 90 01 03 0a 72 90 01 03 70 28 90 01 03 0a 28 90 01 03 0a 0c 08 07 7e 90 01 03 04 28 90 01 03 06 6f 90 01 03 0a de 0a 08 2c 06 08 6f 90 01 03 0a dc de 03 26 de 00 2a 90 00 } //01 00 
		$a_01_1 = {58 00 58 00 47 00 35 00 78 00 4d 00 39 00 57 00 64 00 4b 00 58 00 39 00 32 00 50 00 38 00 30 00 58 00 41 00 4b 00 34 00 7a 00 37 00 38 00 4a 00 } //01 00  XXG5xM9WdKX92P80XAK4z78J
		$a_01_2 = {61 00 62 00 58 00 38 00 5a 00 65 00 68 00 42 00 76 00 51 00 6f 00 38 00 63 00 38 00 75 00 5a 00 77 00 72 00 79 00 } //01 00  abX8ZehBvQo8c8uZwry
		$a_01_3 = {63 00 68 00 65 00 63 00 6b 00 72 00 75 00 6e 00 32 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 73 00 6e 00 6f 00 74 00 } //01 00  checkrun2programsnot
		$a_01_4 = {44 65 63 72 79 70 74 } //01 00  Decrypt
		$a_01_5 = {53 6c 65 65 70 } //01 00  Sleep
		$a_01_6 = {47 65 74 42 79 74 65 73 } //01 00  GetBytes
		$a_01_7 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_8 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00  MemoryStream
		$a_01_9 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //00 00  CreateDecryptor
	condition:
		any of ($a_*)
 
}