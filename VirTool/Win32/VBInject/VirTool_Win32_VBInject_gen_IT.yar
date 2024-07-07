
rule VirTool_Win32_VBInject_gen_IT{
	meta:
		description = "VirTool:Win32/VBInject.gen!IT,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {50 6a 68 e8 90 09 14 00 90 02 03 6a 26 e8 90 01 04 8b d0 8d 90 03 04 04 4d 90 01 01 8d 90 01 04 e8 90 00 } //1
		$a_03_1 = {0f bf c0 33 45 90 01 01 50 e8 90 00 } //1
		$a_01_2 = {68 a4 4e 0e ec 50 e8 4b 00 00 00 83 c4 08 ff 74 24 04 ff d0 ff 74 24 08 50 e8 38 00 00 00 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*2) >=2
 
}