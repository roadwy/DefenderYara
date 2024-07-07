
rule VirTool_Win32_VBInject_gen_HR{
	meta:
		description = "VirTool:Win32/VBInject.gen!HR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {3b cf 74 1f 66 83 39 01 75 19 0f bf f3 2b 71 14 3b 71 10 72 09 } //2
		$a_00_1 = {26 00 48 00 35 00 41 00 34 00 44 00 } //1 &H5A4D
		$a_00_2 = {26 00 48 00 33 00 43 00 } //1 &H3C
		$a_00_3 = {26 00 48 00 34 00 35 00 35 00 30 00 } //1 &H4550
		$a_00_4 = {26 00 48 00 46 00 38 00 } //1 &HF8
	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}