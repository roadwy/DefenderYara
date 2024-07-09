
rule VirTool_Win32_VBInject_gen_GO{
	meta:
		description = "VirTool:Win32/VBInject.gen!GO,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6c 68 ff f5 28 00 00 00 aa 5e ?? ?? ?? ?? aa f5 2c 00 00 00 04 0c ff a3 } //1
		$a_03_1 = {fb 12 fc 0d 6c 6c ff 80 0c 00 fc a0 [0-03] 6c 6c ff 6c 5c ff e0 1c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}