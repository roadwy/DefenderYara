
rule VirTool_Win32_VBInject_gen_GG{
	meta:
		description = "VirTool:Win32/VBInject.gen!GG,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {fc 14 f3 ff 00 fb 12 fc 0d } //1
		$a_01_1 = {f5 07 00 01 00 71 } //1
		$a_03_2 = {f5 40 00 00 00 f5 00 30 00 00 6c 90 01 02 6c 90 01 02 6c 90 01 02 0a 90 00 } //1
		$a_03_3 = {f5 f8 00 00 00 aa f5 28 00 00 00 6c 90 01 02 b2 aa 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}