
rule VirTool_Win32_VBInject_QV{
	meta:
		description = "VirTool:Win32/VBInject.QV,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {58 59 59 59 90 09 06 00 c7 85 ?? ?? ff ff } //1
		$a_03_1 = {66 85 f6 7f ?? 66 81 c6 ff 00 0f ?? ?? 00 00 00 eb ee } //1
		$a_03_2 = {59 50 00 00 e8 ?? ?? ?? ff 90 09 06 00 c7 85 ?? ?? ff ff } //1
		$a_03_3 = {ff e8 00 00 00 90 09 09 00 6a 01 ?? ?? c7 85 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}