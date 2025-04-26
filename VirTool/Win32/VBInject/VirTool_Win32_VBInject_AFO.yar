
rule VirTool_Win32_VBInject_AFO{
	meta:
		description = "VirTool:Win32/VBInject.AFO,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {4b 81 fb 45 02 00 00 0f 8c ?? ?? 00 00 6a 02 5e 3b fb 7f } //1
		$a_03_1 = {66 8b c8 8b c7 99 2b c2 8b 15 ?? ?? ?? ?? 8b 52 10 d1 f8 88 0c 02 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}