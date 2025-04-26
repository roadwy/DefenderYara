
rule VirTool_Win32_CeeInject_gen_AG{
	meta:
		description = "VirTool:Win32/CeeInject.gen!AG,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6a 40 8b 4e 50 8b 56 34 68 00 30 00 00 51 52 50 ff 15 } //2
		$a_01_1 = {b8 68 58 4d 56 } //1
		$a_01_2 = {8a 04 0e b9 e8 03 00 00 03 c2 33 d2 f7 f1 8a 1c 2f 2b da 81 fe } //1
		$a_03_3 = {83 c2 28 03 c8 8b 44 24 ?? 89 54 24 ?? 33 d2 40 66 8b 57 06 89 4c 24 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}