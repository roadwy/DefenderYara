
rule VirTool_Win32_CeeInject_gen_EX{
	meta:
		description = "VirTool:Win32/CeeInject.gen!EX,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {46 81 fe 80 f0 fa 02 74 0f e8 90 01 02 00 00 83 f8 63 75 ed 83 fe 63 75 e8 90 00 } //1
		$a_03_1 = {81 ec 3c 01 00 00 c7 44 24 08 90 01 03 00 c7 44 24 04 00 00 00 00 c7 04 24 01 00 1f 00 e8 90 01 02 00 00 83 ec 0c 85 c0 74 0d 31 c0 8d 65 f4 90 00 } //1
		$a_03_2 = {81 ec 7c 03 00 00 8b 5d 0c 8d 75 94 b9 44 00 00 00 31 c0 89 f7 f3 aa 89 1d 90 01 02 40 00 66 81 3b 4d 5a 74 0a 8d 65 f4 90 00 } //1
		$a_01_3 = {cc cc cc cc 75 f2 c7 06 90 eb 01 e9 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}