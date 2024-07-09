
rule VirTool_Win32_VBInject_AEL{
	meta:
		description = "VirTool:Win32/VBInject.AEL,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {e5 e8 8b 45 ?? 66 c7 40 ?? a4 03 90 09 04 00 66 c7 40 } //1
		$a_03_1 = {ff 66 89 83 ?? ?? 00 00 8b 5d cc 66 89 83 ?? ?? 00 00 90 09 04 00 b8 90 90 90 90 ff } //1
		$a_03_2 = {00 00 31 37 8b 45 ?? 66 c7 80 ?? ?? 00 00 83 c7 8b 45 ?? 66 c7 80 ?? ?? 00 00 04 85 90 09 05 00 66 c7 80 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}