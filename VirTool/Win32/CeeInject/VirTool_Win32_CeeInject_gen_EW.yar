
rule VirTool_Win32_CeeInject_gen_EW{
	meta:
		description = "VirTool:Win32/CeeInject.gen!EW,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 7e 3c 8b 54 37 50 6a 40 03 fe 68 00 30 00 00 } //1
		$a_01_1 = {83 c6 04 3b f0 75 f9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}