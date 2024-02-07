
rule TrojanSpy_Win32_AgentKlog_SW_MTB{
	meta:
		description = "TrojanSpy:Win32/AgentKlog.SW!MTB,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {6e 00 61 00 6d 00 65 00 62 00 72 00 6f 00 } //01 00  namebro
		$a_01_1 = {5b 00 20 00 41 00 4c 00 54 00 44 00 4f 00 57 00 4e 00 20 00 5d 00 } //01 00  [ ALTDOWN ]
		$a_01_2 = {5b 00 45 00 73 00 63 00 61 00 70 00 65 00 5d 00 } //01 00  [Escape]
		$a_01_3 = {57 00 53 00 63 00 72 00 69 00 70 00 74 00 2e 00 53 00 68 00 65 00 6c 00 6c 00 } //01 00  WScript.Shell
		$a_01_4 = {74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 20 00 2f 00 69 00 6d 00 } //01 00  taskkill /im
		$a_01_5 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 74 00 69 00 6d 00 65 00 6f 00 75 00 74 00 2e 00 65 00 78 00 65 00 20 00 2f 00 54 00 20 00 31 00 31 00 20 00 26 00 20 00 44 00 65 00 6c 00 } //01 00  cmd.exe /c timeout.exe /T 11 & Del
		$a_01_6 = {57 00 61 00 6e 00 74 00 54 00 6f 00 43 00 6c 00 65 00 20 00 4c 00 6f 00 67 00 } //00 00  WantToCle Log
	condition:
		any of ($a_*)
 
}