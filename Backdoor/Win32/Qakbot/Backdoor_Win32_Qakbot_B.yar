
rule Backdoor_Win32_Qakbot_B{
	meta:
		description = "Backdoor:Win32/Qakbot.B,SIGNATURE_TYPE_PEHSTR,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {5f 71 62 6f 74 69 6e 6a 2e 65 78 65 } //01 00  _qbotinj.exe
		$a_01_1 = {5f 71 62 6f 74 2e 64 6c 6c } //01 00  _qbot.dll
		$a_01_2 = {5f 71 62 6f 74 6e 74 69 2e 65 78 65 } //01 00  _qbotnti.exe
		$a_01_3 = {6d 61 64 77 61 79 2e 6e 65 74 2f 75 2f 75 70 64 61 74 65 73 } //01 00  madway.net/u/updates
		$a_01_4 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_5 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //01 00  CreateToolhelp32Snapshot
		$a_01_6 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00  WriteProcessMemory
		$a_01_7 = {43 72 65 61 74 65 4d 75 74 65 78 41 } //00 00  CreateMutexA
	condition:
		any of ($a_*)
 
}