
rule VirTool_Win32_VBInject_DD{
	meta:
		description = "VirTool:Win32/VBInject.DD,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {f5 05 00 00 00 c2 f5 02 00 00 00 aa fb 13 fc } //1
		$a_03_1 = {e7 f5 4d 5a 00 00 cc 1c ?? ?? ff } //1
		$a_03_2 = {4a c2 f5 01 00 00 00 aa [0-1f] e7 fb 13 } //1
		$a_03_3 = {f3 e8 00 2b ?? ?? 6c ?? ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}