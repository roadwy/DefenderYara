
rule TrojanDropper_Win32_Small_FI{
	meta:
		description = "TrojanDropper:Win32/Small.FI,SIGNATURE_TYPE_PEHSTR_EXT,20 00 20 00 05 00 00 "
		
	strings :
		$a_02_0 = {81 3c 31 50 45 00 00 0f 90 01 02 00 00 00 90 00 } //10
		$a_02_1 = {5c 5c 2e 5c c7 85 90 01 04 50 68 79 73 90 00 } //10
		$a_02_2 = {6f 6e 64 2e c7 90 01 02 65 78 65 00 90 00 } //10
		$a_00_3 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //1 CreateRemoteThread
		$a_00_4 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_02_2  & 1)*10+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=32
 
}