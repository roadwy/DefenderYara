
rule VirTool_Win32_VBInject_YA{
	meta:
		description = "VirTool:Win32/VBInject.YA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {66 8b 14 78 66 03 14 58 66 81 e2 ff 00 79 09 66 4a 66 81 ca 00 ff 66 42 0f bf da } //1
		$a_01_1 = {81 ff 00 01 00 00 66 8b 0c 78 66 89 0c 58 72 02 ff d6 } //1
		$a_03_2 = {8a 14 11 32 14 5e 88 14 01 [0-18] db 45 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}