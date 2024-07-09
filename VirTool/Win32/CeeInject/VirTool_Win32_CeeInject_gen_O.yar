
rule VirTool_Win32_CeeInject_gen_O{
	meta:
		description = "VirTool:Win32/CeeInject.gen!O,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 07 00 04 00 00 "
		
	strings :
		$a_03_0 = {c7 45 f8 00 00 00 00 eb 09 8b 55 f8 83 c2 01 89 55 f8 83 7d f8 06 73 1b 8b 45 f4 03 45 fc 8b 4d f8 8a 10 32 91 ?? ?? ?? ?? 8b 45 f4 03 45 fc 88 10 eb d6 } //5
		$a_03_1 = {50 6a 00 6a 00 6a 04 6a 00 6a 00 6a 00 8b 4d 08 51 6a 00 ff 15 ?? ?? 40 00 8b 15 ?? ?? 40 00 8b 42 34 50 8b 8d ?? ?? ff ff 51 ff 15 ?? ?? ?? ?? 6a 40 68 00 30 00 00 } //5
		$a_01_2 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_3 = {53 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //1 SetThreadContext
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=7
 
}