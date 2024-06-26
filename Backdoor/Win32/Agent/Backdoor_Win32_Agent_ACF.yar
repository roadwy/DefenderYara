
rule Backdoor_Win32_Agent_ACF{
	meta:
		description = "Backdoor:Win32/Agent.ACF,SIGNATURE_TYPE_PEHSTR_EXT,fffffff0 00 ffffffee 00 0f 00 00 64 00 "
		
	strings :
		$a_00_0 = {73 76 63 68 6f 73 74 2e 65 78 65 } //64 00  svchost.exe
		$a_00_1 = {21 64 64 6f 73 } //0a 00  !ddos
		$a_00_2 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 } //0a 00  explorer.exe
		$a_00_3 = {41 75 74 6f 20 48 6f 74 4b 65 79 20 50 6f 6c 6c 65 72 } //0a 00  Auto HotKey Poller
		$a_00_4 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_00_5 = {5a 4f 4e 45 41 4c 41 52 4d 2e 45 58 45 } //01 00  ZONEALARM.EXE
		$a_00_6 = {5a 41 55 49 4e 53 54 2e 45 58 45 } //01 00  ZAUINST.EXE
		$a_00_7 = {5a 41 54 55 54 4f 52 2e 45 58 45 } //01 00  ZATUTOR.EXE
		$a_00_8 = {57 52 43 54 52 4c 2e 45 58 45 } //01 00  WRCTRL.EXE
		$a_01_9 = {53 65 45 6e 61 62 6c 65 44 65 6c 65 67 61 74 69 6f 6e 50 72 69 76 69 6c 65 67 65 } //01 00  SeEnableDelegationPrivilege
		$a_01_10 = {53 65 52 65 6d 6f 74 65 53 68 75 74 64 6f 77 6e 50 72 69 76 69 6c 65 67 65 } //01 00  SeRemoteShutdownPrivilege
		$a_01_11 = {53 65 41 75 64 69 74 50 72 69 76 69 6c 65 67 65 } //01 00  SeAuditPrivilege
		$a_01_12 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 } //01 00  SeDebugPrivilege
		$a_01_13 = {53 65 53 79 73 74 65 6d 74 69 6d 65 50 72 69 76 69 6c 65 67 65 } //01 00  SeSystemtimePrivilege
		$a_01_14 = {49 6e 74 65 72 6e 65 74 47 65 74 43 6f 6e 6e 65 63 74 65 64 53 74 61 74 65 } //00 00  InternetGetConnectedState
	condition:
		any of ($a_*)
 
}