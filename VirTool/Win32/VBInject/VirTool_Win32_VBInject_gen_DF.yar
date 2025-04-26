
rule VirTool_Win32_VBInject_gen_DF{
	meta:
		description = "VirTool:Win32/VBInject.gen!DF,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {94 80 fe 1c 00 94 80 fe 10 00 aa 08 08 00 8f 24 01 } //1
		$a_01_1 = {f4 24 fc 0d f5 02 00 00 00 04 50 ff fc a0 f4 08 fc 0d f5 03 00 00 00 04 50 ff fc a0 f4 51 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}