
rule TrojanSpy_Win32_Flux_C{
	meta:
		description = "TrojanSpy:Win32/Flux.C,SIGNATURE_TYPE_PEHSTR_EXT,33 00 32 00 06 00 00 "
		
	strings :
		$a_02_0 = {88 16 0f be 09 8b 75 08 03 ca 23 c8 8a 8c ?? ?? ?? ?? ?? 03 f3 30 0e 43 3b } //10
		$a_00_1 = {5c 45 78 70 4c 6f 72 65 72 2e 65 58 65 } //10 \ExpLorer.eXe
		$a_00_2 = {4e 74 4f 70 65 6e 54 68 72 65 61 64 } //10 NtOpenThread
		$a_00_3 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //10 ReadProcessMemory
		$a_00_4 = {4e 74 41 6c 6c 6f 63 61 74 65 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 } //10 NtAllocateVirtualMemory
		$a_00_5 = {41 64 6a 75 73 74 54 6f 6b 65 6e 50 72 69 76 69 6c 65 67 65 73 } //1 AdjustTokenPrivileges
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*10+(#a_00_5  & 1)*1) >=50
 
}