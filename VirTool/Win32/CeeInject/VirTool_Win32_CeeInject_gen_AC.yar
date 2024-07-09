
rule VirTool_Win32_CeeInject_gen_AC{
	meta:
		description = "VirTool:Win32/CeeInject.gen!AC,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_02_0 = {6a 00 32 db ff 15 ?? ?? ?? ?? 8b 48 3c [0-08] 8d ?? ?? 04 [0-08] 8d [0-02] 14 [0-08] 02 [0-04] 89 [0-10] e8 [0-08] 8b 51 ec [0-08] 03 f2 ff 15 [0-10] 6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 68 00 00 00 80 ?? ff 15 [0-30] 8b 7c 24 10 3b fe 76 3c } //1
		$a_08_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
		$a_08_2 = {5a 77 55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e } //1 ZwUnmapViewOfSection
		$a_08_3 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_08_4 = {47 65 74 55 73 65 72 4e 61 6d 65 41 } //1 GetUserNameA
		$a_08_5 = {73 61 6e 64 62 6f 78 } //1 sandbox
		$a_08_6 = {76 6d 77 61 72 65 } //1 vmware
		$a_08_7 = {47 65 74 4d 6f 64 75 6c 65 48 61 6e 64 6c 65 41 } //1 GetModuleHandleA
	condition:
		((#a_02_0  & 1)*1+(#a_08_1  & 1)*1+(#a_08_2  & 1)*1+(#a_08_3  & 1)*1+(#a_08_4  & 1)*1+(#a_08_5  & 1)*1+(#a_08_6  & 1)*1+(#a_08_7  & 1)*1) >=8
 
}