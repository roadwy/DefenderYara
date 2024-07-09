
rule VirTool_Win32_VBInject_gen_DA{
	meta:
		description = "VirTool:Win32/VBInject.gen!DA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {4a c2 f5 01 00 00 00 aa [0-1f] e7 fb 13 } //1
		$a_03_1 = {f5 07 00 01 00 08 08 00 8f 90 09 05 00 66 } //1
		$a_01_2 = {31 0c ff 04 68 ff 3e 0c ff fd c7 6c ff 3e 10 ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}