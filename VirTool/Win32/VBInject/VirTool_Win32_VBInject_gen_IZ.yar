
rule VirTool_Win32_VBInject_gen_IZ{
	meta:
		description = "VirTool:Win32/VBInject.gen!IZ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {b8 75 bb db fb f7 d8 b9 3e 37 f2 3c 83 d1 00 f7 d9 } //1
		$a_03_1 = {66 0f b6 0c 08 8b 95 90 01 02 ff ff 8b 45 90 01 01 66 33 0c 50 90 00 } //1
		$a_03_2 = {8a 0c 1a 8b 5d 90 01 01 8b d3 33 c1 81 e2 ff 00 00 80 79 08 4a 81 ca 00 ff ff ff 42 90 00 } //1
		$a_01_3 = {07 00 01 00 90 09 06 00 c7 85 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}