
rule Trojan_Win32_NetWired_RC_MTB{
	meta:
		description = "Trojan:Win32/NetWired.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {45 3a 5c 63 70 6c 75 73 70 6c 75 73 } //1 E:\cplusplus
		$a_00_1 = {52 65 6c 65 61 73 65 5c 41 64 6f 62 65 } //1 Release\Adobe
		$a_00_2 = {6a 04 68 00 10 00 00 6a 04 6a 00 ff } //1
		$a_00_3 = {6a 40 68 00 30 00 00 } //1
		$a_81_4 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 ReadProcessMemory
		$a_81_5 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}