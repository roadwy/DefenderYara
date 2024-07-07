
rule VirTool_Win32_DelfInject_gen_BA{
	meta:
		description = "VirTool:Win32/DelfInject.gen!BA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {3c e8 0f 84 90 01 02 00 00 e8 90 01 02 ff ff 3c ff 0f 84 90 00 } //1
		$a_03_1 = {32 c1 8b 4d f8 8b 7d 90 01 01 0f b6 4c 39 ff 03 c9 c1 e9 02 32 c1 32 d0 88 55 ef 90 00 } //1
		$a_03_2 = {8b 50 28 8b 45 90 01 01 90 13 03 d0 8b c2 c3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}