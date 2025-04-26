
rule VirTool_Win32_DelfInject_gen_N{
	meta:
		description = "VirTool:Win32/DelfInject.gen!N,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 05 00 00 "
		
	strings :
		$a_01_0 = {46 72 65 65 52 65 73 6f 75 72 63 65 } //10 FreeResource
		$a_00_1 = {47 65 74 4d 6f 64 75 6c 65 48 61 6e 64 6c 65 41 } //10 GetModuleHandleA
		$a_01_2 = {53 45 54 54 49 4e 47 53 } //10 SETTINGS
		$a_02_3 = {8b 45 fc 8a 5c 38 ff 80 e3 0f b8 ?? ?? ?? ?? 8a 44 30 ff 24 0f 32 d8 80 f3 0a 8d 45 fc e8 ?? ?? ?? ?? 8b 55 fc 8a 54 3a ff 80 e2 f0 02 d3 88 54 38 ff 46 83 fe 03 7e 05 be 01 00 00 00 47 ff 4d f4 75 bd } //1
		$a_02_4 = {8b 45 fc 8a 44 18 ff 24 0f 8b 55 ?? 8a 54 32 ff 80 e2 0f 32 c2 88 45 ?? 8d 45 ?? e8 ?? ?? ?? ?? 8b 55 ?? 8a 54 1a ff 80 e2 f0 8a 4d ?? 02 d1 88 54 18 ff 46 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_00_1  & 1)*10+(#a_01_2  & 1)*10+(#a_02_3  & 1)*1+(#a_02_4  & 1)*1) >=31
 
}