
rule VirTool_Win32_VBInject_OZ{
	meta:
		description = "VirTool:Win32/VBInject.OZ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {c7 45 b0 02 00 00 00 8d 45 b0 50 8d 45 c4 50 e8 90 01 03 ff 50 ff 75 d4 90 00 } //1
		$a_01_1 = {b9 48 02 00 00 2b 48 14 } //1
		$a_01_2 = {b9 89 78 00 00 2b 48 14 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}