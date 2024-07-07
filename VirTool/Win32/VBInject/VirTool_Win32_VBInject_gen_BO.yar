
rule VirTool_Win32_VBInject_gen_BO{
	meta:
		description = "VirTool:Win32/VBInject.gen!BO,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {b8 fc 6c 34 fe aa 71 6c fd 00 0d f5 1e 00 00 00 0a } //1
		$a_03_1 = {fb 12 fc 0d 6c 6c ff 80 0c 00 fc a0 90 02 03 6c 6c ff 6c 5c ff e0 1c 90 00 } //1
		$a_03_2 = {f5 41 00 00 00 04 e0 fe 90 01 0c f5 6c 00 00 00 90 01 23 f5 72 00 00 00 90 01 0f f5 74 00 00 00 90 01 0b fb ef 50 fe f5 44 00 00 00 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}