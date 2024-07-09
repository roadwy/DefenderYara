
rule VirTool_Win32_Injector_gen_AN{
	meta:
		description = "VirTool:Win32/Injector.gen!AN,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {b8 68 58 4d 56 } //1
		$a_03_1 = {6a 40 68 00 30 00 00 8b 85 ?? ?? ff ff 8b 48 50 51 8b 95 ?? ?? ff ff 8b 42 34 50 8b 8d ?? ?? ff ff 51 ff 55 } //2
		$a_03_2 = {66 8b 51 06 39 55 ?? 7d 4b 8b 45 f0 8b 48 3c 8b 55 ?? 6b d2 28 } //1
		$a_03_3 = {8a 10 32 94 8d ?? ?? ff ff 8b 45 08 03 85 ?? ?? ff ff 88 10 e9 } //1
		$a_03_4 = {3d 4d 5a 00 00 74 07 33 c0 e9 ?? ?? ?? ?? 8b 4d f0 8b 55 0c 03 51 3c 89 95 ?? ?? ff ff 8b 85 ?? ?? ff ff 81 38 50 45 00 00 74 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=4
 
}