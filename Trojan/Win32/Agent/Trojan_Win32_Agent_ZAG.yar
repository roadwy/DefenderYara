
rule Trojan_Win32_Agent_ZAG{
	meta:
		description = "Trojan:Win32/Agent.ZAG,SIGNATURE_TYPE_PEHSTR,20 00 20 00 08 00 00 "
		
	strings :
		$a_01_0 = {47 65 6e 50 72 6f 74 65 63 74 2e 64 6c 6c } //10 GenProtect.dll
		$a_01_1 = {47 65 6e 50 72 6f 74 65 63 74 2e 65 78 45 } //10 GenProtect.exE
		$a_01_2 = {6d 69 78 65 72 53 65 74 43 6f 6e 74 72 6f 6c 44 65 74 61 69 6c 73 } //5 mixerSetControlDetails
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //5 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_4 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //1 CreateRemoteThread
		$a_01_5 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 ReadProcessMemory
		$a_01_6 = {4f 70 65 6e 50 72 6f 63 65 73 73 } //1 OpenProcess
		$a_01_7 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=32
 
}