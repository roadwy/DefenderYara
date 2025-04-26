
rule VirTool_Win32_VBInject_gen_ET{
	meta:
		description = "VirTool:Win32/VBInject.gen!ET,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_03_0 = {66 b9 ff 00 ?? ?? ?? ?? ?? ?? ?? ?? [0-08] 66 b9 d0 00 } //10
		$a_03_1 = {68 c2 8c 10 c5 68 [0-02] 40 00 } //1
		$a_03_2 = {68 d0 37 10 f2 68 [0-02] 40 00 } //1
		$a_03_3 = {68 c8 46 4a c5 68 [0-02] 40 00 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=12
 
}