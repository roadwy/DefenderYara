
rule TrojanDownloader_Win32_Small_IM{
	meta:
		description = "TrojanDownloader:Win32/Small.IM,SIGNATURE_TYPE_PEHSTR,19 00 19 00 08 00 00 "
		
	strings :
		$a_01_0 = {66 81 3b 4d 5a 74 1a 81 eb 00 00 01 00 66 81 3b 4d 5a 74 0d 81 eb 00 00 01 00 66 81 3b 4d 5a 75 f3 89 5c 24 1c 61 c3 } //10
		$a_01_1 = {25 54 45 4d 50 25 5c 5c 73 76 68 6f 73 74 2e 65 78 65 } //10 %TEMP%\\svhost.exe
		$a_01_2 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 } //1 SeDebugPrivilege
		$a_01_3 = {5a 6f 6e 65 41 6c 61 72 6d 20 53 65 63 75 72 69 74 79 20 41 6c 65 72 74 } //1 ZoneAlarm Security Alert
		$a_01_4 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_5 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //1 CreateRemoteThread
		$a_01_6 = {5a 77 51 75 65 72 79 53 79 73 74 65 6d 49 6e 66 6f 72 6d 61 74 69 6f 6e } //1 ZwQuerySystemInformation
		$a_01_7 = {4e 74 51 75 65 72 79 49 6e 66 6f 72 6d 61 74 69 6f 6e 50 72 6f 63 65 73 73 } //1 NtQueryInformationProcess
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=25
 
}