
rule VirTool_Win32_CeeInject_gen_DA{
	meta:
		description = "VirTool:Win32/CeeInject.gen!DA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 47 50 89 44 24 08 8b 47 34 89 44 24 04 } //2
		$a_03_1 = {73 10 8d 76 00 e8 90 01 04 30 04 33 43 39 fb 72 f3 90 00 } //1
		$a_03_2 = {8b 5f 28 a1 90 01 04 83 ec 14 01 d8 89 85 90 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}