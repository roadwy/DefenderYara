
rule VirTool_Win32_VBInject_DR{
	meta:
		description = "VirTool:Win32/VBInject.DR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {f5 58 59 59 59 59 ?? ff 6c ?? ff [0-0a] f5 04 00 } //1
		$a_03_1 = {f3 e8 00 2b ?? ?? 6c ?? ff } //1
		$a_03_2 = {80 0c 00 fc 90 90 6c [0-0a] c2 [0-08] fc 90 90 fb 11 } //1
		$a_03_3 = {fb 11 fc f0 6e ff 6c 78 ff f5 ?? ?? 00 00 c2 f5 ?? ?? 00 00 90 09 02 00 fc 90 90 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}