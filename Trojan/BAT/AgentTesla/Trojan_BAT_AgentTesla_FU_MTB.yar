
rule Trojan_BAT_AgentTesla_FU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.FU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {02 50 06 03 06 02 50 8e 69 59 03 8e 69 58 91 9c 06 17 58 0a 06 02 50 8e 69 32 e5 } //05 00 
		$a_03_1 = {13 04 12 01 07 8e 69 11 04 8e 69 58 28 90 01 03 06 12 01 11 04 28 90 01 03 06 08 17 58 0c 08 90 00 } //01 00 
		$a_81_2 = {67 65 74 5f 45 6e 74 72 79 50 6f 69 6e 74 } //01 00  get_EntryPoint
		$a_81_3 = {67 65 74 5f 50 69 78 65 6c 46 6f 72 6d 61 74 } //00 00  get_PixelFormat
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_FU_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.FU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 0d 00 00 14 00 "
		
	strings :
		$a_81_0 = {24 31 33 63 63 62 62 38 38 2d 30 33 61 65 2d 34 31 38 64 2d 62 37 35 63 2d 33 31 64 63 62 65 30 36 63 37 35 34 } //14 00  $13ccbb88-03ae-418d-b75c-31dcbe06c754
		$a_81_1 = {24 61 66 34 38 34 37 37 37 2d 39 38 61 66 2d 34 33 35 30 2d 38 61 38 35 2d 35 66 31 34 33 35 64 63 39 34 37 32 } //14 00  $af484777-98af-4350-8a85-5f1435dc9472
		$a_81_2 = {24 37 39 35 34 36 35 63 31 2d 63 61 61 61 2d 34 38 35 61 2d 38 31 35 37 2d 31 33 65 39 66 63 35 62 31 63 36 36 } //14 00  $795465c1-caaa-485a-8157-13e9fc5b1c66
		$a_81_3 = {24 65 33 66 37 62 61 62 33 2d 32 35 64 35 2d 34 64 37 63 2d 62 37 62 32 2d 30 64 64 31 66 36 62 62 36 35 66 33 } //01 00  $e3f7bab3-25d5-4d7c-b7b2-0dd1f6bb65f3
		$a_81_4 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_81_5 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerBrowsableAttribute
		$a_81_6 = {44 65 62 75 67 67 65 72 53 74 65 70 54 68 72 6f 75 67 68 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerStepThroughAttribute
		$a_81_7 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //01 00  DebuggerBrowsableState
		$a_81_8 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_9 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerHiddenAttribute
		$a_81_10 = {41 63 74 69 76 61 74 6f 72 } //01 00  Activator
		$a_81_11 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_81_12 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //00 00  DebuggingModes
	condition:
		any of ($a_*)
 
}