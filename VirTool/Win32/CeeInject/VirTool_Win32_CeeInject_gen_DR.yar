
rule VirTool_Win32_CeeInject_gen_DR{
	meta:
		description = "VirTool:Win32/CeeInject.gen!DR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c0 8a 88 90 01 04 80 f1 90 01 01 88 8c 05 90 01 02 ff ff 40 3d 90 01 02 00 00 72 e8 90 00 } //1
		$a_03_1 = {8b 49 3c 03 4d 0c 8d 8c 31 f8 00 00 00 89 0d 90 01 04 8b 40 34 8b 51 14 ff 71 10 03 41 0c 03 d6 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule VirTool_Win32_CeeInject_gen_DR_2{
	meta:
		description = "VirTool:Win32/CeeInject.gen!DR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {b8 68 58 4d 56 } //1
		$a_01_1 = {42 0f b6 94 15 ec fe ff ff 33 c2 8b 8d e0 fe ff ff 03 4d f8 88 01 } //1
		$a_01_2 = {89 4d f0 8b 55 f0 0f b6 84 15 ec fe ff ff 03 45 f4 25 ff 00 00 80 79 07 48 0d 00 ff ff ff 40 } //2
		$a_03_3 = {bb de c0 00 00 53 90 90 3b c3 58 5b 58 6a 0b 6a 01 e8 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_03_3  & 1)*1) >=5
 
}