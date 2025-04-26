
rule Backdoor_Win32_Agent_CAB{
	meta:
		description = "Backdoor:Win32/Agent.CAB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 07 00 00 "
		
	strings :
		$a_00_0 = {55 8b ec 51 8b 45 08 83 c0 04 50 8b 4d 08 ff 11 89 45 fc 8b 45 fc 8b e5 5d c2 04 00 } //10
		$a_00_1 = {00 64 74 72 2e 64 6c 6c } //5 搀牴搮汬
		$a_00_2 = {00 68 6f 6f 6b 2e 64 6c 6c } //5
		$a_01_3 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_01_4 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //1 CreateRemoteThread
		$a_01_5 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_6 = {5c 43 53 43 68 65 61 74 5c 44 72 69 76 65 72 } //-100 \CSCheat\Driver
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*5+(#a_00_2  & 1)*5+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*-100) >=23
 
}