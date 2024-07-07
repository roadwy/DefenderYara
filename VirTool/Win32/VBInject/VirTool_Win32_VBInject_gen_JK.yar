
rule VirTool_Win32_VBInject_gen_JK{
	meta:
		description = "VirTool:Win32/VBInject.gen!JK,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {b9 60 00 00 00 ff d6 8b 0d 90 01 04 8b 51 0c 8b 79 14 2b d7 b9 e8 00 00 00 88 02 ff d6 8b 0d 90 01 04 8b 51 0c 8b 79 14 2b d7 b9 4e 00 00 00 88 42 01 ff d6 90 00 } //1
		$a_01_1 = {00 4e 74 41 6c 6c 6f 63 61 74 65 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 00 } //1
		$a_01_2 = {83 e1 01 89 4d fc 24 fe 50 89 45 08 8b 10 ff 52 04 b9 04 00 02 80 33 f6 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}