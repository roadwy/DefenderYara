
rule VirTool_Win32_CeeInject_gen_LG{
	meta:
		description = "VirTool:Win32/CeeInject.gen!LG,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {07 00 01 00 50 ff 75 ?? ff 95 } //1
		$a_03_1 = {8b 47 28 03 45 ?? 89 85 90 09 03 00 ff 55 } //1
		$a_03_2 = {0f b7 47 06 ff 45 ?? 83 45 ?? 28 39 45 ?? 7c c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}