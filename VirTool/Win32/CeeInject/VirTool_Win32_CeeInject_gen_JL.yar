
rule VirTool_Win32_CeeInject_gen_JL{
	meta:
		description = "VirTool:Win32/CeeInject.gen!JL,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 56 57 68 40 42 0f 00 6a 00 ff 15 } //1
		$a_01_1 = {83 c1 04 83 ee 01 75 f3 8d 78 06 bb 49 e8 01 00 eb 09 } //1
		$a_01_2 = {c1 ef 05 8b d9 c1 e3 04 33 fb 05 47 86 c8 61 8b d8 83 e3 03 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}