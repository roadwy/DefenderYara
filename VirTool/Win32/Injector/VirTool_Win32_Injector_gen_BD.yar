
rule VirTool_Win32_Injector_gen_BD{
	meta:
		description = "VirTool:Win32/Injector.gen!BD,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 08 8d 0c 06 8b c6 99 f7 3d ?? ?? ?? ?? 8a 82 ?? ?? ?? ?? 30 01 46 3b 74 24 0c 7e e1 } //2
		$a_01_1 = {01 3e 8b 06 c6 00 e9 83 c4 0c ff 06 8b 06 8b cf 2b c8 8d 4c 19 fc 89 08 83 c8 ff 2b c7 01 06 } //2
		$a_03_2 = {c7 45 0c f8 00 00 00 a1 ?? ?? ?? ?? 8b ?? 3c [0-10] 8b ?? 0c [0-07] 03 ?? 03 c7 } //1
		$a_01_3 = {8b 40 3c 03 45 0c 53 8d 84 38 f8 00 00 00 } //1
		$a_01_4 = {6b c0 28 8b 49 3c 05 f8 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}