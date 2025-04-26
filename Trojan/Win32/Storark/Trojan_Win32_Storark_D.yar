
rule Trojan_Win32_Storark_D{
	meta:
		description = "Trojan:Win32/Storark.D,SIGNATURE_TYPE_PEHSTR_EXT,19 00 16 00 0a 00 00 "
		
	strings :
		$a_00_0 = {40 65 63 68 6f 20 6f 66 66 0d 0a 3a 4c 6f 6f 70 0d 0a 61 74 74 72 69 62 20 22 00 00 22 20 2d 72 20 2d 61 20 2d 73 20 2d 68 0d 0a 64 65 6c 20 22 00 00 00 00 22 0d 0a 69 66 20 65 78 69 73 74 20 22 00 00 00 22 20 67 6f 74 6f 20 4c 6f 6f 70 0d 0a 64 65 6c 20 25 30 } //10
		$a_00_1 = {76 65 72 63 6c 73 69 64 2e 65 78 65 } //5 verclsid.exe
		$a_00_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 65 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 45 78 65 63 75 74 65 48 6f 6f 6b 73 } //3 Software\Microsoft\Windows\CurrentVersion\explorer\ShellExecuteHooks
		$a_00_3 = {41 70 70 49 6e 69 74 5f 44 4c 4c 73 } //3 AppInit_DLLs
		$a_00_4 = {4e 6f 41 75 74 6f 55 70 64 61 74 65 } //2 NoAutoUpdate
		$a_00_5 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 53 68 61 72 65 64 41 63 63 65 73 73 5c 50 61 72 61 6d 65 74 65 72 73 5c 46 69 72 65 77 61 6c 6c 50 6f 6c 69 63 79 5c 53 74 61 6e 64 61 72 64 50 72 6f 66 69 6c 65 } //1 SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile
		$a_01_6 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_7 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //1 InternetOpenUrlA
		$a_01_8 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //1 SetWindowsHookExA
		$a_01_9 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*5+(#a_00_2  & 1)*3+(#a_00_3  & 1)*3+(#a_00_4  & 1)*2+(#a_00_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=22
 
}