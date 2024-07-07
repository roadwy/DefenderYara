
rule VirTool_Win32_Foger_gen_A{
	meta:
		description = "VirTool:Win32/Foger.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,14 00 0f 00 0d 00 00 "
		
	strings :
		$a_02_0 = {55 4b 4c 4e 4d 45 4d 4c 2c 47 5a 47 90 02 15 45 58 50 4c 4f 52 45 52 2e 45 58 45 90 02 15 49 45 58 50 4c 4f 52 45 2e 45 58 45 90 02 20 6b 6a 32 33 61 77 61 72 78 79 64 6e 33 34 73 2e 74 6d 70 90 02 10 54 4f 54 41 4c 43 4d 44 2e 45 58 45 90 00 } //3
		$a_00_1 = {6b 6a 32 33 61 77 61 72 78 79 64 6e 33 34 73 2e 74 6d 70 } //3 kj23awarxydn34s.tmp
		$a_00_2 = {66 75 77 61 72 78 79 75 73 2e 64 6c 6c } //3 fuwarxyus.dll
		$a_00_3 = {44 4c 4c 4e 61 6d 65 22 3d 22 5c 5c 5c 5c 66 75 77 61 72 78 79 75 73 2e 64 6c 6c } //3 DLLName"="\\\\fuwarxyus.dll
		$a_00_4 = {4c 6f 67 6f 6e 22 3d 22 57 69 6e 6c 6f 67 6f 6e 4c 6f 67 6f 6e 45 76 65 6e 74 } //1 Logon"="WinlogonLogonEvent
		$a_00_5 = {5b 48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e 5c 4e 6f 74 69 66 79 5c 63 72 79 70 74 33 32 73 65 74 5d } //1 [HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\crypt32set]
		$a_00_6 = {4c 6f 67 6f 66 66 22 3d 22 57 69 6e 6c 6f 67 6f 6e 4c 6f 67 6f 66 66 45 76 65 6e 74 } //1 Logoff"="WinlogonLogoffEvent
		$a_00_7 = {53 63 72 65 65 6e 53 61 76 65 72 22 3d 22 57 69 6e 6c 6f 67 6f 6e 53 63 72 65 65 6e 53 61 76 65 72 45 76 65 6e 74 } //1 ScreenSaver"="WinlogonScreenSaverEvent
		$a_00_8 = {53 74 61 72 74 75 70 22 3d 22 57 69 6e 6c 6f 67 6f 6e 53 74 61 72 74 75 70 45 76 65 6e 74 } //1 Startup"="WinlogonStartupEvent
		$a_00_9 = {53 68 75 74 64 6f 77 6e 22 3d 22 57 69 6e 6c 6f 67 6f 6e 53 68 75 74 64 6f 77 6e 45 76 65 6e 74 } //1 Shutdown"="WinlogonShutdownEvent
		$a_00_10 = {53 74 61 72 74 53 68 65 6c 6c 22 3d 22 57 69 6e 6c 6f 67 6f 6e 53 74 61 72 74 53 68 65 6c 6c 45 76 65 6e 74 } //1 StartShell"="WinlogonStartShellEvent
		$a_00_11 = {49 6d 70 65 72 73 6f 6e 61 74 65 22 3d 64 77 6f 72 64 3a 30 30 30 30 30 30 30 30 } //1 Impersonate"=dword:00000000
		$a_00_12 = {41 73 79 6e 63 68 72 6f 6e 6f 75 73 22 3d 64 77 6f 72 64 3a 30 30 30 30 30 30 30 31 } //1 Asynchronous"=dword:00000001
	condition:
		((#a_02_0  & 1)*3+(#a_00_1  & 1)*3+(#a_00_2  & 1)*3+(#a_00_3  & 1)*3+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1+(#a_00_12  & 1)*1) >=15
 
}