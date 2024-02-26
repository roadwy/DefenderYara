
rule Trojan_BAT_AgentTesla_NB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {5d 59 d2 9c 11 04 17 58 13 04 11 04 20 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NB_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {20 42 11 f3 ff 5a 09 61 2b af 28 90 01 03 06 20 90 01 03 15 2b 00 28 90 01 03 2b 12 00 28 90 01 03 0a 20 90 01 03 c4 2b 00 28 90 01 03 2b 28 90 01 03 0a 25 28 90 01 03 06 28 90 01 03 0a 73 90 01 03 0a 28 90 01 03 0a 90 00 } //01 00 
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //01 00  DownloadString
		$a_01_2 = {48 54 54 50 53 65 72 76 69 63 65 2e 65 78 65 } //00 00  HTTPService.exe
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NB_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 05 00 "
		
	strings :
		$a_03_0 = {64 fe 0c 23 00 1f 19 62 60 fe 90 01 02 00 20 90 01 03 00 fe 90 01 02 00 20 90 01 03 00 5f 5a 90 00 } //01 00 
		$a_01_1 = {46 00 6f 00 6c 00 64 00 65 00 72 00 43 00 72 00 65 00 61 00 74 00 6f 00 72 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //01 00  FolderCreator.Resources
		$a_01_2 = {57 00 69 00 6e 00 46 00 6f 00 72 00 6d 00 73 00 5f 00 52 00 65 00 63 00 75 00 72 00 73 00 69 00 76 00 65 00 46 00 6f 00 72 00 6d 00 43 00 72 00 65 00 61 00 74 00 65 00 } //01 00  WinForms_RecursiveFormCreate
		$a_01_3 = {57 00 69 00 6e 00 46 00 6f 00 72 00 6d 00 73 00 5f 00 53 00 65 00 65 00 49 00 6e 00 6e 00 65 00 72 00 45 00 78 00 63 00 65 00 70 00 74 00 69 00 6f 00 6e 00 } //00 00  WinForms_SeeInnerException
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NB_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_81_0 = {63 6d 64 20 2f 63 20 74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 74 20 2f 69 6d 20 66 69 6c 65 73 5c 73 2d 69 72 65 63 6f 76 65 72 79 2e 65 78 65 } //01 00  cmd /c taskkill /f /t /im files\s-irecovery.exe
		$a_81_1 = {54 4f 4f 4c 5f 41 44 56 52 41 4e 44 } //01 00  TOOL_ADVRAND
		$a_81_2 = {45 78 70 6c 6f 69 74 69 6e 67 20 77 69 74 68 20 6c 69 6d 65 72 61 31 6e } //01 00  Exploiting with limera1n
		$a_81_3 = {68 74 74 70 3a 2f 2f 69 68 38 73 6e 30 77 2e 63 6f 6d } //01 00  http://ih8sn0w.com
		$a_81_4 = {5c 66 69 6c 65 73 5c 6c 6c 62 2e 33 67 73 2e 64 66 75 } //01 00  \files\llb.3gs.dfu
		$a_81_5 = {69 42 6f 6f 74 79 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  iBooty.Resources.resources
		$a_81_6 = {41 64 6f 62 65 20 49 6d 61 67 65 52 65 61 64 79 71 } //01 00  Adobe ImageReadyq
		$a_81_7 = {74 45 58 74 53 6f 66 74 77 61 72 65 } //01 00  tEXtSoftware
		$a_81_8 = {5f 74 68 69 73 6d 73 67 74 78 74 } //01 00  _thismsgtxt
		$a_81_9 = {53 54 41 52 54 46 5f 55 53 45 53 48 4f 57 57 49 4e 44 4f 57 } //00 00  STARTF_USESHOWWINDOW
	condition:
		any of ($a_*)
 
}