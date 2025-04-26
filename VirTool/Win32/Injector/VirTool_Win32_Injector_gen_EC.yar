
rule VirTool_Win32_Injector_gen_EC{
	meta:
		description = "VirTool:Win32/Injector.gen!EC,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {b8 fc fd fe ff b9 40 00 00 00 89 04 8d ?? ?? ?? ?? 2d 04 04 04 04 49 75 f1 } //1
		$a_03_1 = {30 0e 46 4f 75 ce 33 c0 bf ?? ?? ?? ?? b9 40 00 00 00 fc f3 ab } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}