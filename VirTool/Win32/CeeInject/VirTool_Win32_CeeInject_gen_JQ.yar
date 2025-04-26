
rule VirTool_Win32_CeeInject_gen_JQ{
	meta:
		description = "VirTool:Win32/CeeInject.gen!JQ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 07 00 00 "
		
	strings :
		$a_03_0 = {4e 81 ce 00 ff ff ff 46 0f b6 54 b4 ?? 8b b4 24 ?? ?? ?? ?? 30 14 30 40 3b c5 72 } //1
		$a_03_1 = {33 d2 8b c6 f7 f3 0f b6 14 2a 03 54 8c ?? 03 fa 81 e7 ff 00 00 80 79 } //1
		$a_03_2 = {0f b6 0c 11 8d 84 bd ?? ?? ff ff 03 08 03 d9 81 e3 ff 00 00 80 79 } //1
		$a_03_3 = {49 81 c9 00 ff ff ff 41 8a 8c 8d ?? ?? ff ff 30 08 46 3b 75 ?? 0f 82 } //1
		$a_03_4 = {72 f2 8b 45 f8 85 90 09 0e 00 33 c0 f6 90 90 ?? ?? ?? ?? 40 3d ?? ?? 00 00 } //1
		$a_03_5 = {4e 75 f5 33 c0 c6 45 f4 00 8d 7d f5 ab ab 66 ab aa 90 09 0d 00 be ?? ?? ?? ?? 6a 00 ff 15 } //1
		$a_01_6 = {4e 74 50 6f 77 65 72 49 6e 66 6f 72 6d 61 74 69 6f 6e 00 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1+(#a_01_6  & 1)*1) >=2
 
}