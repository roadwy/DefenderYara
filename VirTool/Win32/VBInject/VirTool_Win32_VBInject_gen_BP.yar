
rule VirTool_Win32_VBInject_gen_BP{
	meta:
		description = "VirTool:Win32/VBInject.gen!BP,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 08 00 00 "
		
	strings :
		$a_01_0 = {f4 58 fc 0d f5 00 00 00 00 04 58 ff fc a0 f4 59 fc 0d } //1
		$a_03_1 = {f5 58 59 59 59 59 90 01 01 ff 6c 6c ff 90 00 } //1
		$a_01_2 = {6c 70 fe 6c 64 fe aa 71 9c fd } //4
		$a_01_3 = {6c 78 fe 6c 6c fe aa 71 ec fd } //4
		$a_01_4 = {6c 68 fe 6c 5c fe aa 71 8c fd } //4
		$a_01_5 = {6c 74 fe 6c 68 fe aa 71 a0 fd } //4
		$a_03_6 = {f4 1e a9 e7 90 01 19 66 68 ff 18 00 90 00 } //1
		$a_01_7 = {6b 6e ff 6b 6c ff fb 12 e7 04 44 ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*4+(#a_01_3  & 1)*4+(#a_01_4  & 1)*4+(#a_01_5  & 1)*4+(#a_03_6  & 1)*1+(#a_01_7  & 1)*1) >=5
 
}