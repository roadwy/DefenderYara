
rule VirTool_BAT_Antisow_A{
	meta:
		description = "VirTool:BAT/Antisow.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {4b 61 7a 79 52 6f 6f 74 6b 69 74 } //01 00  KazyRootkit
		$a_01_1 = {48 69 64 65 50 72 6f 63 65 73 73 } //01 00  HideProcess
		$a_01_2 = {48 69 64 65 52 65 67 69 73 74 72 79 56 61 6c 75 65 } //01 00  HideRegistryValue
		$a_01_3 = {2f 00 63 00 20 00 65 00 63 00 68 00 6f 00 20 00 5b 00 7a 00 6f 00 6e 00 65 00 54 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00 5d 00 5a 00 6f 00 6e 00 65 00 49 00 44 00 20 00 3d 00 20 00 32 00 20 00 3e 00 20 00 22 00 } //01 00  /c echo [zoneTransfer]ZoneID = 2 > "
		$a_01_4 = {22 00 3a 00 5a 00 4f 00 4e 00 45 00 2e 00 69 00 64 00 65 00 6e 00 74 00 69 00 66 00 69 00 65 00 72 00 20 00 26 00 20 00 65 00 78 00 69 00 74 00 } //00 00  ":ZONE.identifier & exit
		$a_00_5 = {78 d7 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_BAT_Antisow_A_2{
	meta:
		description = "VirTool:BAT/Antisow.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 0c 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 6e 74 69 45 6d 75 6c 61 74 69 6f 6e } //01 00  AntiEmulation
		$a_01_1 = {41 6e 74 69 53 61 6e 64 62 6f 78 69 65 } //01 00  AntiSandboxie
		$a_01_2 = {44 65 74 65 63 74 57 50 45 } //01 00  DetectWPE
		$a_01_3 = {44 65 74 65 63 74 57 69 72 65 73 68 61 72 6b } //01 00  DetectWireshark
		$a_01_4 = {44 69 73 61 62 6c 65 55 41 43 } //01 00  DisableUAC
		$a_01_5 = {44 6f 77 6e 52 75 6e } //01 00  DownRun
		$a_01_6 = {48 69 64 64 65 6e 53 74 61 72 74 75 70 } //01 00  HiddenStartup
		$a_01_7 = {4b 69 6c 6c 50 72 6f 63 } //01 00  KillProc
		$a_01_8 = {47 65 74 49 6e 6a 65 63 74 69 6f 6e 50 61 74 68 } //01 00  GetInjectionPath
		$a_01_9 = {2d 00 6b 00 65 00 79 00 68 00 69 00 64 00 65 00 } //01 00  -keyhide
		$a_01_10 = {2d 00 70 00 72 00 6f 00 63 00 68 00 69 00 64 00 65 00 } //01 00  -prochide
		$a_01_11 = {2d 00 70 00 72 00 6f 00 63 00 6b 00 69 00 6c 00 6c 00 } //00 00  -prockill
		$a_00_12 = {87 10 00 00 } //c2 7c 
	condition:
		any of ($a_*)
 
}