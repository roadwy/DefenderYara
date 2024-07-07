
rule VirTool_Win32_VBInject_PJ_bit{
	meta:
		description = "VirTool:Win32/VBInject.PJ!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {c7 00 55 89 e5 e8 a1 90 01 03 00 c7 40 04 a4 03 00 00 90 00 } //1
		$a_03_1 = {31 37 83 c7 8b 35 90 01 03 00 c7 86 90 01 02 00 00 04 85 c0 75 90 00 } //1
		$a_03_2 = {f4 c3 00 00 a1 90 01 03 00 c7 80 90 01 02 00 00 00 00 00 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}