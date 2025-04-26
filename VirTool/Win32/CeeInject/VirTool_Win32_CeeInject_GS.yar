
rule VirTool_Win32_CeeInject_GS{
	meta:
		description = "VirTool:Win32/CeeInject.GS,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {c1 c0 07 32 03 43 80 3b 00 75 f5 } //1
		$a_01_1 = {66 ad 66 a9 00 30 74 08 25 ff 0f 00 00 01 14 07 e2 ee } //1
		$a_01_2 = {03 d6 88 3a fe c7 66 46 66 81 fe 00 01 75 ed } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}