
rule VirTool_Win32_VBInject_OX{
	meta:
		description = "VirTool:Win32/VBInject.OX,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {40 00 8b 45 08 8b 00 ff 75 08 ff 50 28 89 45 90 01 01 83 7d 90 00 } //1
		$a_01_1 = {8d 45 e8 50 8b 45 08 05 80 01 00 00 50 8b 45 08 05 7c 01 00 00 } //1
		$a_01_2 = {6a 02 58 6b c0 0d 8b 4d 08 8b 49 6c 66 c7 04 01 } //1
		$a_01_3 = {8b 45 e8 8b 00 ff 75 e8 ff 50 28 db e2 89 45 e4 83 7d e4 00 7d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}