
rule VirTool_Win32_VBInject_gen_HY{
	meta:
		description = "VirTool:Win32/VBInject.gen!HY,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 86 a4 01 00 00 03 ca 8b 96 fc 00 00 00 89 0c 90 } //1
		$a_03_1 = {89 04 8a 8b 07 90 09 06 00 8b 86 38 01 00 00 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}