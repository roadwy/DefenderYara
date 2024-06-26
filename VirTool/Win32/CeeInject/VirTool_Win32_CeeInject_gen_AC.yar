
rule VirTool_Win32_CeeInject_gen_AC{
	meta:
		description = "VirTool:Win32/CeeInject.gen!AC,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 00 32 db ff 15 90 01 04 8b 48 3c 90 02 08 8d 90 01 02 04 90 02 08 8d 90 02 02 14 90 02 08 02 90 02 04 89 90 02 10 e8 90 02 08 8b 51 ec 90 02 08 03 f2 ff 15 90 02 10 6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 68 00 00 00 80 90 01 01 ff 15 90 02 30 8b 7c 24 10 3b fe 76 3c 90 00 } //01 00 
		$a_08_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //01 00  VirtualAlloc
		$a_08_2 = {5a 77 55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e } //01 00  ZwUnmapViewOfSection
		$a_08_3 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00  WriteProcessMemory
		$a_08_4 = {47 65 74 55 73 65 72 4e 61 6d 65 41 } //01 00  GetUserNameA
		$a_08_5 = {73 61 6e 64 62 6f 78 } //01 00  sandbox
		$a_08_6 = {76 6d 77 61 72 65 } //01 00  vmware
		$a_08_7 = {47 65 74 4d 6f 64 75 6c 65 48 61 6e 64 6c 65 41 } //00 00  GetModuleHandleA
	condition:
		any of ($a_*)
 
}