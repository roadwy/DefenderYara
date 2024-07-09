
rule VirTool_Win32_VBInject_AGS_bit{
	meta:
		description = "VirTool:Win32/VBInject.AGS!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f 6e 5c 24 04 [0-20] 0f ef d9 [0-20] 0f 7e db [0-20] 81 fb ?? ?? ?? ?? 75 } //2
		$a_03_1 = {8b 5c 24 08 [0-20] 39 18 75 [0-20] 8b 5c 24 0c [0-20] 39 58 04 75 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}