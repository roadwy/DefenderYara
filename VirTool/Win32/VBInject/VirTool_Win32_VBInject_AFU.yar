
rule VirTool_Win32_VBInject_AFU{
	meta:
		description = "VirTool:Win32/VBInject.AFU,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {6a 07 58 3b f8 0f 8f ?? 00 00 00 c7 45 ?? 01 00 00 00 b8 ?? ?? 00 00 39 45 90 1b 01 0f 8f } //1
		$a_03_1 = {ff 6a 01 58 03 f8 e9 ?? ff ff ff ff 35 ?? ?? ?? 00 e8 90 09 1c 00 50 8d 45 ?? 50 6a ?? e8 ?? ?? ?? ff 83 c4 ?? ff 45 ?? 6a ?? 58 01 45 ?? e9 } //1
		$a_03_2 = {88 04 11 8d 90 09 0e 00 e8 ?? ?? ?? ff 8b 0d ?? ?? ?? 00 8b 55 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}