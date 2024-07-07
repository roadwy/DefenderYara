
rule VirTool_Win32_CeeInject_gen_DY{
	meta:
		description = "VirTool:Win32/CeeInject.gen!DY,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {83 7d 08 01 75 0a b8 90 01 04 e9 e7 00 00 00 83 7d 08 02 75 0a b8 90 01 04 e9 d7 00 00 00 90 00 } //1
		$a_03_1 = {8b 4d f0 8a 94 0d 90 01 04 88 94 05 90 01 04 8b 45 f0 8a 8d 90 01 04 88 8c 05 90 01 04 e9 79 ff ff ff 90 00 } //1
		$a_03_2 = {6a 09 6a 01 e8 90 01 04 83 c4 08 a3 90 01 04 6a 44 6a 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}