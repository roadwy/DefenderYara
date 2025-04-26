
rule VirTool_Win32_VBInject_gen_GC{
	meta:
		description = "VirTool:Win32/VBInject.gen!GC,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b f0 81 ee 4d 5a 00 00 f7 de 1b f6 46 f7 de 8d 85 } //1
		$a_01_1 = {2d 50 45 00 00 f7 d8 1b c0 40 f7 d8 23 f0 66 85 f6 74 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}