
rule Trojan_BAT_AgentTesla_EA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 03 00 "
		
	strings :
		$a_01_0 = {01 57 94 02 28 09 02 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 1b 00 00 00 04 } //01 00 
		$a_01_1 = {41 70 70 44 6f 6d 61 69 6e } //01 00  AppDomain
		$a_01_2 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //01 00  get_CurrentDomain
		$a_01_3 = {67 65 74 5f 42 61 73 65 44 69 72 65 63 74 6f 72 79 } //00 00  get_BaseDirectory
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_EA_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_02_0 = {00 20 00 10 00 00 8d 90 01 04 0b 73 90 01 03 0a 0c 00 00 06 07 16 20 00 10 00 00 6f 90 01 03 0a 0d 09 16 fe 02 13 04 11 04 2c 0c 00 08 07 16 09 6f 90 01 03 0a 00 00 00 09 16 fe 02 13 05 11 05 2d d0 08 6f 90 01 03 0a 13 06 de 16 90 00 } //01 00 
		$a_81_1 = {47 5a 49 44 45 4b 4b 4b 4b } //01 00  GZIDEKKKK
		$a_81_2 = {47 5a 69 70 53 74 72 65 61 6d } //00 00  GZipStream
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_EA_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,21 00 21 00 0f 00 00 14 00 "
		
	strings :
		$a_81_0 = {24 39 33 63 33 66 35 66 66 2d 37 61 37 35 2d 34 39 63 31 2d 62 65 39 37 2d 34 37 63 34 31 61 32 31 66 39 65 63 } //14 00  $93c3f5ff-7a75-49c1-be97-47c41a21f9ec
		$a_81_1 = {24 32 34 64 31 37 36 61 66 2d 65 62 61 65 2d 34 31 31 35 2d 38 30 61 63 2d 30 39 64 38 38 30 66 34 35 64 39 36 } //14 00  $24d176af-ebae-4115-80ac-09d880f45d96
		$a_81_2 = {24 66 32 35 35 65 32 32 36 2d 35 64 36 66 2d 34 36 32 38 2d 38 34 39 34 2d 30 34 65 61 31 34 64 34 31 33 38 37 } //05 00  $f255e226-5d6f-4628-8494-04ea14d41387
		$a_81_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //05 00  CreateInstance
		$a_81_4 = {41 63 74 69 76 61 74 6f 72 } //01 00  Activator
		$a_81_5 = {44 61 74 61 54 72 65 65 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //01 00  DataTree.My.Resources
		$a_81_6 = {49 6e 6d 61 63 6f 6c 50 72 6f 79 65 63 74 6f 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //01 00  InmacolProyecto.My.Resources
		$a_81_7 = {50 6f 6d 66 5f 55 70 6c 6f 61 64 65 72 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //01 00  Pomf_Uploader.My.Resources
		$a_81_8 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_81_9 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerBrowsableAttribute
		$a_81_10 = {44 65 62 75 67 67 65 72 53 74 65 70 54 68 72 6f 75 67 68 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerStepThroughAttribute
		$a_81_11 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //01 00  DebuggerBrowsableState
		$a_81_12 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerHiddenAttribute
		$a_81_13 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_81_14 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //00 00  DebuggingModes
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_EA_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 11 00 00 14 00 "
		
	strings :
		$a_81_0 = {24 38 34 61 37 32 32 62 31 2d 38 63 34 32 2d 34 35 66 33 2d 61 33 33 63 2d 66 64 64 31 36 64 64 33 37 38 38 66 } //14 00  $84a722b1-8c42-45f3-a33c-fdd16dd3788f
		$a_81_1 = {24 37 30 30 62 31 35 36 31 2d 62 37 32 31 2d 34 66 36 34 2d 38 38 35 35 2d 39 36 37 37 36 66 61 32 63 38 32 38 } //14 00  $700b1561-b721-4f64-8855-96776fa2c828
		$a_81_2 = {24 39 63 36 64 63 32 33 66 2d 61 32 37 39 2d 34 37 63 37 2d 61 39 66 35 2d 61 61 63 63 64 34 32 62 65 65 63 62 } //14 00  $9c6dc23f-a279-47c7-a9f5-aaccd42beecb
		$a_81_3 = {24 35 61 35 37 33 36 36 34 2d 34 37 36 64 2d 34 37 63 37 2d 62 38 61 33 2d 63 39 31 39 33 61 32 32 65 33 37 65 } //01 00  $5a573664-476d-47c7-b8a3-c9193a22e37e
		$a_81_4 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_81_5 = {4c 65 61 76 65 4d 61 6e 61 67 65 72 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  LeaveManager.Resources.resources
		$a_81_6 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerBrowsableAttribute
		$a_81_7 = {53 6b 6c 67 65 68 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  Sklgeh.Properties.Resources.resources
		$a_81_8 = {44 65 62 75 67 67 65 72 53 74 65 70 54 68 72 6f 75 67 68 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerStepThroughAttribute
		$a_81_9 = {4c 65 76 65 6c 45 64 69 74 6f 72 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  LevelEditor.Resources.resources
		$a_81_10 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //01 00  DebuggerBrowsableState
		$a_81_11 = {48 65 6c 70 65 72 73 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //01 00  Helpers.My.Resources
		$a_81_12 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_13 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerHiddenAttribute
		$a_81_14 = {41 63 74 69 76 61 74 6f 72 } //01 00  Activator
		$a_81_15 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_81_16 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //00 00  DebuggingModes
	condition:
		any of ($a_*)
 
}