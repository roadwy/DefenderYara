
rule TrojanSpy_Win32_Agent_PO{
	meta:
		description = "TrojanSpy:Win32/Agent.PO,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c } //1 SYSTEM\CurrentControlSet\Services\
		$a_01_1 = {52 65 67 69 73 74 65 72 53 65 72 76 69 63 65 43 74 72 6c 48 61 6e 64 6c 65 72 41 } //1 RegisterServiceCtrlHandlerA
		$a_01_2 = {41 64 6a 75 73 74 54 6f 6b 65 6e 50 72 69 76 69 6c 65 67 65 73 } //1 AdjustTokenPrivileges
		$a_01_3 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //1 CreateRemoteThread
		$a_01_4 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 } //1 SeDebugPrivilege
		$a_01_5 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //1 ShellExecuteA
		$a_01_6 = {33 36 30 54 72 61 79 2e 65 78 65 } //1 360Tray.exe
		$a_01_7 = {33 36 30 53 61 66 65 2e 65 78 65 } //1 360Safe.exe
		$a_01_8 = {69 66 20 65 78 69 73 74 20 22 } //1 if exist "
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}