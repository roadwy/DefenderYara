
rule TrojanDropper_Win32_ProcessInjector_A{
	meta:
		description = "TrojanDropper:Win32/ProcessInjector.A,SIGNATURE_TYPE_PEHSTR,49 00 49 00 0b 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //10 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 49 45 58 50 4c 4f 52 45 2e 45 58 45 } //10 \Program Files\Internet Explorer\IEXPLORE.EXE
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e } //10 Software\Microsoft\Windows NT\CurrentVersion\Winlogon
		$a_01_3 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 } //10 SeDebugPrivilege
		$a_01_4 = {44 69 73 61 62 6c 65 52 65 67 69 73 74 72 79 54 6f 6f 6c 73 } //10 DisableRegistryTools
		$a_01_5 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //10 WriteProcessMemory
		$a_01_6 = {4e 74 41 6c 6c 6f 63 61 74 65 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 } //10 NtAllocateVirtualMemory
		$a_01_7 = {4b 76 4d 6f 6e 2e 65 78 65 } //1 KvMon.exe
		$a_01_8 = {63 6d 64 2e 65 78 65 20 2f 63 20 64 65 6c 20 } //1 cmd.exe /c del 
		$a_01_9 = {57 69 6e 73 74 61 30 5c 44 65 66 61 75 6c 74 } //1 Winsta0\Default
		$a_01_10 = {73 79 73 74 65 6d 33 32 5c 75 73 65 72 69 6e 69 74 2e 65 78 65 2c } //1 system32\userinit.exe,
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=73
 
}