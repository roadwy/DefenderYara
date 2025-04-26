
rule PWS_Win32_OnLineGames_ZDN{
	meta:
		description = "PWS:Win32/OnLineGames.ZDN,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 07 00 00 "
		
	strings :
		$a_03_0 = {68 4b e1 22 00 50 ff 15 ?? ?? ?? 00 85 c0 74 10 ff 15 ?? ?? ?? 00 85 c0 75 06 b8 01 00 00 00 c3 33 c0 c3 } //5
		$a_00_1 = {00 00 00 00 20 67 6f 74 6f 20 74 72 79 20 0a 00 69 66 20 65 78 69 73 74 20 25 73 00 64 65 6c 20 25 73 20 0a 00 00 00 00 3a 74 72 79 20 0a 00 00 } //4
		$a_00_2 = {00 48 4d 5f 4d 45 53 53 57 4f 57 } //2
		$a_01_3 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //1 KeServiceDescriptorTable
		$a_00_4 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //1 CreateRemoteThread
		$a_00_5 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_00_6 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
	condition:
		((#a_03_0  & 1)*5+(#a_00_1  & 1)*4+(#a_00_2  & 1)*2+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=10
 
}