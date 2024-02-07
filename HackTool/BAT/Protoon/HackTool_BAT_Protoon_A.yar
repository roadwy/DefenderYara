
rule HackTool_BAT_Protoon_A{
	meta:
		description = "HackTool:BAT/Protoon.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 72 6f 74 6f 6e 43 72 79 70 74 } //01 00  ProtonCrypt
		$a_01_1 = {46 69 6c 65 6d 61 6e 61 67 65 72 43 6c 69 65 6e 74 } //01 00  FilemanagerClient
		$a_01_2 = {48 61 6e 64 6c 65 4c 6f 63 6b 46 69 6c 65 43 6f 6d 6d 61 6e 64 73 } //01 00  HandleLockFileCommands
		$a_01_3 = {48 61 6e 64 6c 65 53 65 6e 64 43 6f 6d 6d 61 6e 64 73 } //00 00  HandleSendCommands
		$a_00_4 = {78 70 } //00 00  xp
	condition:
		any of ($a_*)
 
}
rule HackTool_BAT_Protoon_A_2{
	meta:
		description = "HackTool:BAT/Protoon.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 79 73 74 65 6d 54 6f 6f 6c 73 43 6c 69 65 6e 74 } //01 00  SystemToolsClient
		$a_01_1 = {48 61 6e 64 6c 65 43 6f 6e 73 6f 6c 65 43 6f 6d 6d 61 6e 64 73 } //01 00  HandleConsoleCommands
		$a_01_2 = {48 61 6e 64 6c 65 54 61 73 6b 4d 61 6e 61 67 65 72 43 6f 6d 6d 61 6e 64 73 } //01 00  HandleTaskManagerCommands
		$a_01_3 = {48 61 6e 64 6c 65 52 65 67 69 73 74 72 79 43 6f 6d 6d 61 6e 64 73 } //00 00  HandleRegistryCommands
		$a_00_4 = {78 77 } //00 00  xw
	condition:
		any of ($a_*)
 
}
rule HackTool_BAT_Protoon_A_3{
	meta:
		description = "HackTool:BAT/Protoon.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 75 6e 6e 79 54 6f 6f 6c 73 43 6c 69 65 6e 74 } //01 00  FunnyToolsClient
		$a_01_1 = {48 61 72 64 77 61 72 65 43 6f 6d 6d 61 6e 64 73 } //01 00  HardwareCommands
		$a_01_2 = {48 61 6e 64 6c 65 4d 69 73 63 43 6f 6d 6d 61 6e 64 73 } //01 00  HandleMiscCommands
		$a_01_3 = {73 00 65 00 74 00 20 00 43 00 44 00 41 00 75 00 64 00 69 00 6f 00 20 00 64 00 6f 00 6f 00 72 00 20 00 6f 00 70 00 65 00 6e 00 } //00 00  set CDAudio door open
		$a_00_4 = {78 78 } //00 00  xx
	condition:
		any of ($a_*)
 
}
rule HackTool_BAT_Protoon_A_4{
	meta:
		description = "HackTool:BAT/Protoon.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {4b 65 79 62 6f 61 72 64 20 4c 6f 67 20 2d 20 50 72 6f 74 6f 6e 20 52 41 54 } //01 00  Keyboard Log - Proton RAT
		$a_01_1 = {5c 00 50 00 72 00 6f 00 74 00 6f 00 6e 00 5c 00 4b 00 42 00 4c 00 6f 00 67 00 73 00 } //01 00  \Proton\KBLogs
		$a_01_2 = {7b 00 30 00 7d 00 5c 00 4b 00 42 00 2d 00 7b 00 31 00 7d 00 2e 00 7b 00 32 00 7d 00 2e 00 7b 00 33 00 7d 00 2e 00 6c 00 6f 00 67 00 } //00 00  {0}\KB-{1}.{2}.{3}.log
		$a_00_3 = {78 } //8d 00  x
	condition:
		any of ($a_*)
 
}
rule HackTool_BAT_Protoon_A_5{
	meta:
		description = "HackTool:BAT/Protoon.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 61 6e 64 6c 65 43 68 61 74 43 6f 6d 6d 61 6e 64 73 } //01 00  HandleChatCommands
		$a_01_1 = {48 61 6e 64 6c 65 55 70 6c 6f 61 64 41 6e 64 45 78 65 63 75 74 65 43 6f 6d 6d 61 6e 64 73 } //01 00  HandleUploadAndExecuteCommands
		$a_01_2 = {48 61 6e 64 6c 65 44 6f 77 6e 6c 6f 61 64 41 6e 64 45 78 65 63 75 74 65 43 6f 6d 6d 61 6e 64 73 } //01 00  HandleDownloadAndExecuteCommands
		$a_01_3 = {48 61 6e 64 6c 65 56 69 73 69 74 57 65 62 73 69 74 65 48 69 64 64 65 6e 6c 79 43 6f 6d 6d 61 6e 64 73 } //00 00  HandleVisitWebsiteHiddenlyCommands
		$a_00_4 = {78 c8 } //00 00 
	condition:
		any of ($a_*)
 
}
rule HackTool_BAT_Protoon_A_6{
	meta:
		description = "HackTool:BAT/Protoon.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {56 69 64 65 6f 53 6f 75 72 63 65 73 43 6f 6d 6d 61 6e 64 73 } //01 00  VideoSourcesCommands
		$a_01_1 = {50 61 73 73 77 6f 72 64 52 65 63 6f 76 65 72 79 43 6f 6d 6d 61 6e 64 73 } //01 00  PasswordRecoveryCommands
		$a_01_2 = {52 65 6d 6f 74 65 44 65 73 6b 74 6f 70 43 6f 6d 6d 61 6e 64 73 } //01 00  RemoteDesktopCommands
		$a_01_3 = {53 75 72 76 65 69 6c 6c 61 6e 63 65 43 6c 69 65 6e 74 } //01 00  SurveillanceClient
		$a_01_4 = {5c 00 47 00 6f 00 6f 00 67 00 6c 00 65 00 5c 00 43 00 68 00 72 00 6f 00 6d 00 65 00 5c 00 55 00 73 00 65 00 72 00 20 00 44 00 61 00 74 00 61 00 5c 00 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 5c 00 4c 00 6f 00 67 00 69 00 6e 00 20 00 44 00 61 00 74 00 61 00 } //00 00  \Google\Chrome\User Data\Default\Login Data
		$a_00_5 = {78 1c } //01 00  ᱸ
	condition:
		any of ($a_*)
 
}
rule HackTool_BAT_Protoon_A_7{
	meta:
		description = "HackTool:BAT/Protoon.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 6c 69 65 6e 74 50 6c 75 67 69 6e } //01 00  ClientPlugin
		$a_01_1 = {50 69 70 65 64 65 73 74 72 6f 79 65 64 } //01 00  Pipedestroyed
		$a_01_2 = {52 00 69 00 73 00 70 00 73 00 42 00 34 00 38 00 33 00 45 00 65 00 32 00 78 00 37 00 31 00 56 00 34 00 64 00 79 00 6d 00 30 00 51 00 3d 00 3d 00 } //01 00  RispsB483Ee2x71V4dym0Q==
		$a_01_3 = {4c 00 6f 00 61 00 64 00 65 00 64 00 20 00 70 00 6c 00 75 00 67 00 69 00 6e 00 3a 00 20 00 7b 00 30 00 7d 00 2c 00 20 00 63 00 61 00 63 00 68 00 65 00 64 00 3a 00 20 00 7b 00 31 00 7d 00 } //01 00  Loaded plugin: {0}, cached: {1}
		$a_01_4 = {22 00 20 00 2f 00 53 00 43 00 20 00 4f 00 4e 00 43 00 45 00 20 00 2f 00 53 00 54 00 20 00 30 00 30 00 3a 00 30 00 30 00 20 00 2f 00 54 00 52 00 20 00 22 00 27 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 27 00 20 00 2f 00 43 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 22 00 22 00 20 00 22 00 } //01 00  " /SC ONCE /ST 00:00 /TR "'cmd.exe' /C start "" "
		$a_01_5 = {5c 00 4c 00 6f 00 67 00 2e 00 74 00 78 00 74 00 } //00 00  \Log.txt
		$a_00_6 = {5d 04 00 } //00 98 
	condition:
		any of ($a_*)
 
}