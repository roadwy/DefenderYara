
rule Backdoor_Win32_Agent_PD{
	meta:
		description = "Backdoor:Win32/Agent.PD,SIGNATURE_TYPE_PEHSTR,ffffffb0 01 ffffffb0 01 0a 00 00 "
		
	strings :
		$a_01_0 = {57 49 4e 4c 4f 47 4f 4e } //100 WINLOGON
		$a_01_1 = {73 65 76 65 6e 2d 65 6c 65 76 65 6e } //100 seven-eleven
		$a_01_2 = {5c 54 72 6f 6a 61 6e 53 5f 50 2e 65 78 65 } //100 \TrojanS_P.exe
		$a_01_3 = {54 52 4f 4a 41 4e 20 56 45 52 20 31 2e 30 20 42 55 49 4c 44 } //100 TROJAN VER 1.0 BUILD
		$a_01_4 = {53 65 53 68 75 74 64 6f 77 6e 50 72 69 76 69 6c 65 67 65 } //10 SeShutdownPrivilege
		$a_01_5 = {53 65 74 20 63 64 41 75 64 69 6f 20 64 6f 6f 72 20 6f 70 65 6e 20 77 61 69 74 } //10 Set cdAudio door open wait
		$a_01_6 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //10 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_7 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //1 UnhookWindowsHookEx
		$a_01_8 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_01_9 = {49 6e 74 65 72 6e 65 74 47 65 74 43 6f 6e 6e 65 63 74 65 64 53 74 61 74 65 } //1 InternetGetConnectedState
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100+(#a_01_2  & 1)*100+(#a_01_3  & 1)*100+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=432
 
}