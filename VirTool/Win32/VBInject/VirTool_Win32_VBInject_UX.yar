
rule VirTool_Win32_VBInject_UX{
	meta:
		description = "VirTool:Win32/VBInject.UX,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0c 00 06 00 00 "
		
	strings :
		$a_01_0 = {c7 85 74 ff ff ff 58 59 59 59 ff d3 } //1
		$a_01_1 = {c7 85 78 ff ff ff e8 00 00 00 } //1
		$a_01_2 = {c7 85 78 ff ff ff 68 00 00 00 } //1
		$a_01_3 = {c7 85 78 ff ff ff c3 00 00 00 } //1
		$a_00_4 = {26 00 48 00 34 00 35 00 35 00 30 00 } //5 &H4550
		$a_00_5 = {26 00 48 00 35 00 41 00 34 00 44 00 } //5 &H5A4D
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*5+(#a_00_5  & 1)*5) >=12
 
}