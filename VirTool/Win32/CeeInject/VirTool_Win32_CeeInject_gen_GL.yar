
rule VirTool_Win32_CeeInject_gen_GL{
	meta:
		description = "VirTool:Win32/CeeInject.gen!GL,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {ff 30 eb de 8b 55 08 8b 02 89 45 f8 8b 45 f8 ff d0 } //1
		$a_01_1 = {0f be 02 33 c1 8b 4d 08 03 4d f4 88 01 } //1
		$a_03_2 = {8b 08 c6 01 e9 8b 55 ?? 8b 02 83 c0 01 8b 4d ?? 89 01 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}