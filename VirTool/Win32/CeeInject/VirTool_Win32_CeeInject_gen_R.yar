
rule VirTool_Win32_CeeInject_gen_R{
	meta:
		description = "VirTool:Win32/CeeInject.gen!R,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 56 28 03 56 34 8b 4c 24 14 8d 44 24 68 50 51 89 94 24 20 01 00 00 ff 15 } //1
		$a_01_1 = {8b d1 83 e2 0f 8a 14 3a 30 14 29 83 c1 01 3b c8 72 ee } //1
		$a_01_2 = {8a c2 b4 3e 66 f7 f1 } //1
		$a_00_3 = {69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 62 6c 61 0a 64 65 6c } //1 晩攠楸瑳∠猥•潧潴戠慬搊汥
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}