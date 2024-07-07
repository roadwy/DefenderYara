
rule VirTool_Win32_VBInject_gen_ED{
	meta:
		description = "VirTool:Win32/VBInject.gen!ED,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6c 70 fe 6c 64 fe aa 71 90 fd } //1
		$a_01_1 = {fd 69 4c ff fb a4 3c ff fc 22 6c 5c ff fc 90 fb 96 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}