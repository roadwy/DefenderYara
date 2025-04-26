
rule VirTool_Win32_VBInject_gen_FG{
	meta:
		description = "VirTool:Win32/VBInject.gen!FG,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6c 38 fe 6c 2c fe aa 71 2c fd } //1
		$a_01_1 = {f5 07 00 01 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}