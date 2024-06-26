
rule Trojan_BAT_AgentTesla_EJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 0e 00 00 0a 00 "
		
	strings :
		$a_02_0 = {0a 0b 00 07 17 73 90 01 03 0a 0c 00 08 06 16 06 8e 69 6f 90 01 03 0a 00 08 6f 90 01 03 0a 00 07 6f 90 01 03 0a 0d de 16 90 00 } //01 00 
		$a_81_1 = {43 6f 6d 70 72 65 73 73 47 5a 69 70 } //01 00  CompressGZip
		$a_81_2 = {44 65 73 65 72 69 61 6c 69 7a 65 4a 73 6f 6e } //01 00  DeserializeJson
		$a_81_3 = {45 6e 63 6f 64 65 42 61 73 65 36 34 } //01 00  EncodeBase64
		$a_81_4 = {54 6f 4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00  ToMemoryStream
		$a_81_5 = {44 65 63 6f 6d 70 72 65 73 73 47 5a 69 70 } //01 00  DecompressGZip
		$a_81_6 = {54 6f 58 44 6f 63 75 6d 65 6e 74 } //01 00  ToXDocument
		$a_81_7 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_8 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00  InvokeMember
		$a_81_9 = {47 65 74 42 79 74 65 73 } //01 00  GetBytes
		$a_81_10 = {45 78 74 72 61 63 74 47 5a 69 70 54 6f 44 69 72 65 63 74 6f 72 79 } //01 00  ExtractGZipToDirectory
		$a_81_11 = {54 6f 42 79 74 65 41 72 72 61 79 } //01 00  ToByteArray
		$a_81_12 = {45 6e 63 72 79 70 74 52 53 41 } //01 00  EncryptRSA
		$a_81_13 = {4f 70 65 6e 52 65 61 64 } //00 00  OpenRead
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_EJ_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.EJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 10 00 00 14 00 "
		
	strings :
		$a_81_0 = {24 64 36 32 64 61 36 36 64 2d 31 64 65 34 2d 34 62 36 62 2d 62 62 63 66 2d 30 36 66 61 33 66 34 63 34 30 30 64 } //14 00  $d62da66d-1de4-4b6b-bbcf-06fa3f4c400d
		$a_81_1 = {24 35 37 37 62 30 65 32 66 2d 32 62 37 61 2d 34 63 39 64 2d 62 62 61 30 2d 62 66 63 64 66 62 64 30 31 36 37 65 } //14 00  $577b0e2f-2b7a-4c9d-bba0-bfcdfbd0167e
		$a_81_2 = {24 61 38 33 30 63 65 38 35 2d 64 39 35 65 2d 34 31 66 64 2d 62 39 36 31 2d 31 65 62 65 64 34 32 62 62 66 35 66 } //14 00  $a830ce85-d95e-41fd-b961-1ebed42bbf5f
		$a_81_3 = {24 35 61 38 35 65 35 35 61 2d 32 64 37 37 2d 34 63 37 36 2d 38 37 38 38 2d 66 61 37 61 61 35 38 62 31 34 62 37 } //01 00  $5a85e55a-2d77-4c76-8788-fa7aa58b14b7
		$a_81_4 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_81_5 = {5f 32 30 34 38 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //01 00  _2048.Properties.Resources
		$a_81_6 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerBrowsableAttribute
		$a_81_7 = {42 61 74 74 6c 65 53 68 69 70 5f 57 69 6e 46 6f 72 6d 73 41 70 70 2e 4d 61 69 6e 46 6f 72 6d 2e 72 65 73 6f 75 72 63 65 73 } //01 00  BattleShip_WinFormsApp.MainForm.resources
		$a_81_8 = {44 65 62 75 67 67 65 72 53 74 65 70 54 68 72 6f 75 67 68 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerStepThroughAttribute
		$a_81_9 = {44 75 6e 67 65 6f 6e 5f 53 68 65 65 68 61 6e 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //01 00  Dungeon_Sheehan.Form1.resources
		$a_81_10 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //01 00  DebuggerBrowsableState
		$a_81_11 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_12 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerHiddenAttribute
		$a_81_13 = {41 63 74 69 76 61 74 6f 72 } //01 00  Activator
		$a_81_14 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_81_15 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //00 00  DebuggingModes
	condition:
		any of ($a_*)
 
}