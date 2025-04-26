
rule VirTool_Win32_Injector_gen_BC{
	meta:
		description = "VirTool:Win32/Injector.gen!BC,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 39 99 87 e4 ff 35 } //1
		$a_03_1 = {ff 76 34 8d 7e 34 ff 75 ?? ff 55 ?? 6a 40 68 00 30 00 00 ff 76 50 } //1
		$a_03_2 = {32 10 32 d1 88 10 8b 45 ?? 40 3b c6 89 45 ?? 72 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}