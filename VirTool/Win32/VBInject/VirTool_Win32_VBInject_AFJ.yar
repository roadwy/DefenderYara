
rule VirTool_Win32_VBInject_AFJ{
	meta:
		description = "VirTool:Win32/VBInject.AFJ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 05 00 00 "
		
	strings :
		$a_03_0 = {8b 54 1d 00 (66 0f|0f) } //1
		$a_01_1 = {31 c2 66 0f } //1
		$a_03_2 = {89 54 1d 00 (66 0f|0f) } //1
		$a_03_3 = {43 83 c3 03 81 7c 1d fc ?? ?? ?? ?? 75 } //1
		$a_01_4 = {61 00 78 00 69 00 6c 00 37 00 33 00 35 00 39 00 2e 00 63 00 6f 00 6d 00 2f 00 } //-1 axil7359.com/
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*-1) >=3
 
}