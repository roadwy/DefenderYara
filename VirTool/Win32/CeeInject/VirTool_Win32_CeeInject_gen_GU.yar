
rule VirTool_Win32_CeeInject_gen_GU{
	meta:
		description = "VirTool:Win32/CeeInject.gen!GU,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {07 00 01 00 90 09 07 00 c7 84 24 } //1
		$a_01_1 = {8b 16 8b 07 6a 40 68 00 30 00 00 51 52 50 ff 94 24 } //1
		$a_03_2 = {03 51 3c 89 55 ?? 8b 45 90 1b 00 0f b7 48 06 89 4d ?? 8b 55 90 1b 00 81 c2 f8 00 00 00 } //1
		$a_01_3 = {8b 48 3c 03 c8 0f b7 51 06 8d 81 f8 00 00 00 8d 4a ff 3b cf 76 05 6b c9 28 03 c1 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}