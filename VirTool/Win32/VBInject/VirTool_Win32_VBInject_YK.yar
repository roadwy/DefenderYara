
rule VirTool_Win32_VBInject_YK{
	meta:
		description = "VirTool:Win32/VBInject.YK,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {b8 bb 17 44 ac f7 d8 b9 ec 3e 87 74 83 d1 00 f7 d9 8b 95 b0 f9 ff ff 8b 75 e0 89 04 d6 89 4c d6 04 c7 85 b0 f9 ff ff 10 00 00 00 83 bd b0 f9 ff ff 58 73 09 83 a5 58 f9 ff ff 00 eb 0b } //1
		$a_03_1 = {b8 1b ff ff ff f7 d8 b9 97 2d 38 58 83 d1 00 f7 d9 8b 95 90 01 04 8b 90 03 09 04 90 04 01 02 b5 35 90 01 04 75 90 01 01 89 04 d6 89 4c d6 04 e9 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}