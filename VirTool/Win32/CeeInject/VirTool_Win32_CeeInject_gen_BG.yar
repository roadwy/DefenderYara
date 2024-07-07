
rule VirTool_Win32_CeeInject_gen_BG{
	meta:
		description = "VirTool:Win32/CeeInject.gen!BG,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 c6 28 45 66 8b 4a 02 3b e9 7e c6 8b 4c 24 90 01 01 68 90 01 04 8b 51 10 03 d7 90 00 } //1
		$a_03_1 = {66 81 3b 4d 5a 0f 85 90 01 04 8b 73 3c 03 f3 81 3e 50 45 00 00 74 0c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}