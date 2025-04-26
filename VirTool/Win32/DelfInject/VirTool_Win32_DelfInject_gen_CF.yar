
rule VirTool_Win32_DelfInject_gen_CF{
	meta:
		description = "VirTool:Win32/DelfInject.gen!CF,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {64 ff 30 64 89 20 33 c0 89 45 f8 8b f3 66 81 3e 4d 5a 0f 85 ?? ?? ?? ?? 8b fb 03 7e 3c 81 3f 50 45 00 00 } //1
		$a_01_1 = {68 f8 00 00 00 57 8b c3 03 46 3c 50 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule VirTool_Win32_DelfInject_gen_CF_2{
	meta:
		description = "VirTool:Win32/DelfInject.gen!CF,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 00 6a 04 6a 00 6a 00 6a 00 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 6a 00 e8 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 02 00 01 00 } //1
		$a_03_1 = {8b 45 fc 8a 44 18 ff 24 0f 8b 55 f8 8a 54 32 ff 80 e2 0f 32 c2 88 45 ?? 8d 45 fc e8 ?? ?? ?? ?? 8b 55 fc 8a 54 1a ff 80 e2 f0 8a 4d ?? 02 d1 88 54 18 ff } //1
		$a_03_2 = {8b df 85 db 7c ?? 43 33 f6 a1 ?? ?? ?? ?? 8a 04 30 a2 ?? ?? ?? ?? a0 90 1b 02 34 } //1
		$a_03_3 = {b8 00 00 00 00 40 3d 00 e9 a4 35 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 75 e9 } //1
		$a_03_4 = {8a 04 30 a2 ?? ?? ?? ?? a0 90 1b 00 c0 c8 ?? a2 90 1b 00 a1 ?? ?? ?? ?? 8a 15 90 1b 00 88 14 30 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=2
 
}