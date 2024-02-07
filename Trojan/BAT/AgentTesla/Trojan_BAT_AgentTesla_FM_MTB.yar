
rule Trojan_BAT_AgentTesla_FM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.FM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {41 6c 74 69 75 6d 4d 61 6e 61 67 65 72 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  AltiumManager.Resources.resources
		$a_81_1 = {41 6c 74 69 75 6d 4d 61 6e 61 67 65 72 2e 50 6c 61 74 69 6e 69 75 6d 2e 72 65 73 6f 75 72 63 65 73 } //01 00  AltiumManager.Platinium.resources
		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_3 = {47 65 74 44 6f 6d 61 69 6e } //01 00  GetDomain
		$a_81_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_5 = {43 6f 6e 76 65 72 74 } //01 00  Convert
		$a_81_6 = {41 63 74 69 76 61 74 6f 72 } //00 00  Activator
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_FM_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.FM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 11 00 00 14 00 "
		
	strings :
		$a_81_0 = {24 31 66 31 31 64 61 30 63 2d 33 61 30 36 2d 34 36 32 62 2d 61 32 61 34 2d 35 30 61 32 61 36 64 34 31 33 36 36 } //14 00  $1f11da0c-3a06-462b-a2a4-50a2a6d41366
		$a_81_1 = {24 36 62 37 39 38 31 32 39 2d 63 61 65 31 2d 34 62 36 38 2d 62 65 33 37 2d 36 30 32 66 63 63 64 62 39 65 62 33 } //14 00  $6b798129-cae1-4b68-be37-602fccdb9eb3
		$a_81_2 = {24 35 39 61 37 39 38 36 66 2d 37 61 62 61 2d 34 32 31 37 2d 62 35 63 35 2d 37 62 63 35 62 31 31 62 39 66 33 63 } //14 00  $59a7986f-7aba-4217-b5c5-7bc5b11b9f3c
		$a_81_3 = {24 36 61 37 62 35 34 66 66 2d 30 36 36 62 2d 34 30 37 62 2d 62 61 36 33 2d 30 38 32 34 33 32 32 37 63 36 39 61 } //01 00  $6a7b54ff-066b-407b-ba63-08243227c69a
		$a_81_4 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_81_5 = {51 75 61 6e 4c 79 44 69 65 6d 53 56 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  QuanLyDiemSV.Resources.resources
		$a_81_6 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerBrowsableAttribute
		$a_81_7 = {47 72 61 70 68 69 63 73 55 74 69 6c 69 74 79 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //01 00  GraphicsUtility.Form1.resources
		$a_81_8 = {44 65 62 75 67 67 65 72 53 74 65 70 54 68 72 6f 75 67 68 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerStepThroughAttribute
		$a_81_9 = {43 6c 75 6d 73 79 50 72 6f 6f 66 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //01 00  ClumsyProof.My.Resources
		$a_81_10 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //01 00  DebuggerBrowsableState
		$a_81_11 = {4d 65 74 65 6f 72 55 69 4c 69 62 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //01 00  MeteorUiLib.My.Resources
		$a_81_12 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_13 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerHiddenAttribute
		$a_81_14 = {41 63 74 69 76 61 74 6f 72 } //01 00  Activator
		$a_81_15 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_81_16 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //00 00  DebuggingModes
	condition:
		any of ($a_*)
 
}