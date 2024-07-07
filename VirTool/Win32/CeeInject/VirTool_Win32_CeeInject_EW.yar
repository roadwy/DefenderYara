
rule VirTool_Win32_CeeInject_EW{
	meta:
		description = "VirTool:Win32/CeeInject.EW,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 78 3a 5c 77 65 72 64 6f 6e 2e 70 64 62 00 } //2
		$a_01_1 = {00 66 6f 72 73 2e 64 61 74 00 } //1
		$a_03_2 = {00 00 37 9e c7 45 90 09 03 00 c7 45 90 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=4
 
}