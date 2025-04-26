
rule VirTool_Win32_Injector_gen_CT{
	meta:
		description = "VirTool:Win32/Injector.gen!CT,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 40 b8 00 10 00 00 0d 00 20 00 00 50 8b 45 ?? 83 c0 50 ff 30 6a 00 8b 45 ?? ff 30 ff 55 ?? 83 f8 00 } //1
		$a_03_1 = {05 b0 00 00 00 89 18 c7 45 ?? 00 00 00 00 c7 45 ?? 74 65 78 74 c7 45 ?? 64 43 6f 6e c7 45 ?? 68 72 65 61 c7 45 ?? 53 65 74 54 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}