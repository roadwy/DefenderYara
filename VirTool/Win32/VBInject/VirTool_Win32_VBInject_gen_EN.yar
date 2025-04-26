
rule VirTool_Win32_VBInject_gen_EN{
	meta:
		description = "VirTool:Win32/VBInject.gen!EN,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {f4 00 fb fd 23 ?? ff 2a 31 ?? ff 2f ?? ff 04 ?? ff } //1
		$a_03_1 = {8a 3c 00 f5 f8 00 00 00 aa f5 28 00 00 00 76 ?? ?? b2 aa } //1
		$a_03_2 = {f5 07 00 01 00 22 ?? 00 8f 00 00 [0-02] 3a } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}