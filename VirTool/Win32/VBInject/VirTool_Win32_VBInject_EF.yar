
rule VirTool_Win32_VBInject_EF{
	meta:
		description = "VirTool:Win32/VBInject.EF,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {e7 f5 4d 5a 00 00 c7 c3 1c } //1
		$a_01_1 = {f4 05 a9 c1 fb 12 fc 0d } //1
		$a_00_2 = {34 00 44 00 35 00 41 00 39 00 30 00 30 00 20 00 } //1 4D5A900 
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}