
rule VirTool_Win32_VBInject_gen_BV{
	meta:
		description = "VirTool:Win32/VBInject.gen!BV,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {6c 78 fe 6c 6c fe aa 71 a4 fd } //1
		$a_00_1 = {55 00 70 00 67 00 72 00 63 00 4e 00 70 00 6d 00 61 00 63 00 71 00 71 00 4b 00 63 00 6b 00 6d 00 70 00 77 00 00 00 } //1
		$a_00_2 = {51 00 63 00 72 00 52 00 66 00 70 00 63 00 5f 00 62 00 41 00 6d 00 6c 00 72 00 63 00 76 00 72 00 00 00 } //1
		$a_01_3 = {f4 02 a9 e7 71 70 ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}