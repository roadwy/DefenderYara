
rule VirTool_Win32_Toksteal_A{
	meta:
		description = "VirTool:Win32/Toksteal.A,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 07 00 07 00 00 "
		
	strings :
		$a_03_0 = {89 45 f8 8b 0d ?? ?? ?? ?? 89 4d f4 } //2
		$a_03_1 = {8b f4 6a 00 6a 03 8d 55 f8 52 a1 ?? ?? ?? ?? 50 8b 4d 08 51 ff 15 ?? ?? ?? ?? 3b f4 e8 ?? ?? ?? ?? 8b f4 8d 55 fc 52 8b 45 fc 50 6a 03 } //5
		$a_01_2 = {57 00 69 00 6e 00 33 00 32 00 5f 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 } //1 Win32_Process
		$a_01_3 = {72 00 6f 00 6f 00 74 00 5c 00 63 00 69 00 6d 00 76 00 32 00 20 00 20 00 } //1 root\cimv2  
		$a_01_4 = {77 6d 69 70 72 76 73 65 2e 65 78 65 } //1 wmiprvse.exe
		$a_01_5 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_6 = {44 75 70 6c 69 63 61 74 65 48 61 6e 64 6c 65 } //1 DuplicateHandle
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}