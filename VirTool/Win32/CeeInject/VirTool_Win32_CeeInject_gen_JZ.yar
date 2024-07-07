
rule VirTool_Win32_CeeInject_gen_JZ{
	meta:
		description = "VirTool:Win32/CeeInject.gen!JZ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 46 3c 8b 4c 30 34 03 c6 8b de 2b d9 0f 84 } //1
		$a_03_1 = {0f b7 4d 06 40 83 90 01 01 28 3b c1 89 44 24 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}