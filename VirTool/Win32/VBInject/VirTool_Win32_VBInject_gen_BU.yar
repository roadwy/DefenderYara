
rule VirTool_Win32_VBInject_gen_BU{
	meta:
		description = "VirTool:Win32/VBInject.gen!BU,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {94 80 fc 1c 00 94 80 fc 10 00 aa 71 9c fd } //1
		$a_00_1 = {55 00 70 00 67 00 72 00 63 00 4e 00 70 00 6d 00 61 00 63 00 71 00 71 00 4b 00 63 00 6b 00 6d 00 70 00 77 00 00 00 } //1
		$a_00_2 = {4c 00 72 00 51 00 63 00 72 00 41 00 6d 00 6c 00 72 00 63 00 76 00 72 00 52 00 66 00 70 00 63 00 5f 00 62 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}