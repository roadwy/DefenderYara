
rule TrojanSpy_Win32_Fgspy_A{
	meta:
		description = "TrojanSpy:Win32/Fgspy.A,SIGNATURE_TYPE_PEHSTR_EXT,22 00 22 00 08 00 00 "
		
	strings :
		$a_00_0 = {52 69 6e 67 30 50 6f 72 74 2e 73 79 73 } //10 Ring0Port.sys
		$a_00_1 = {48 69 64 64 65 6e 5f 50 72 6f 63 5f 44 6c 6c 2e 64 6c 6c } //10 Hidden_Proc_Dll.dll
		$a_00_2 = {4b 54 48 69 64 65 } //10 KTHide
		$a_00_3 = {72 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 5c 00 6d 00 61 00 63 00 68 00 69 00 6e 00 65 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 5c 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 5c 00 4b 00 65 00 72 00 6e 00 65 00 6c 00 50 00 6f 00 72 00 74 00 } //1 registry\machine\system\CurrentControlSet\Services\KernelPort
		$a_00_4 = {50 72 6f 63 65 73 73 33 32 4e 65 78 74 } //1 Process32Next
		$a_00_5 = {50 72 6f 63 65 73 73 33 32 46 69 72 73 74 } //1 Process32First
		$a_01_6 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_00_7 = {5a 77 51 75 65 72 79 53 79 73 74 65 6d 49 6e 66 6f 72 6d 61 74 69 6f 6e } //1 ZwQuerySystemInformation
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_01_6  & 1)*1+(#a_00_7  & 1)*1) >=34
 
}