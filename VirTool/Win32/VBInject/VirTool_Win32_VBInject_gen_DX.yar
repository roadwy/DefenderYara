
rule VirTool_Win32_VBInject_gen_DX{
	meta:
		description = "VirTool:Win32/VBInject.gen!DX,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {e7 f5 4d 5a 00 00 c7 c3 1c } //1
		$a_03_1 = {f5 07 00 01 00 71 ?? ?? 1e } //1
		$a_01_2 = {6c 74 ff ae f5 05 00 00 00 ae 71 74 ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}