
rule VirTool_Win32_VBInject_AFN{
	meta:
		description = "VirTool:Win32/VBInject.AFN,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {3b 41 40 75 05 e9 ?? ?? ?? ?? c7 45 fc 12 00 00 00 e8 ?? ?? ?? ?? c7 45 fc 13 00 00 00 c7 85 ?? ff ff ff ?? ?? ?? ?? 6a 04 8b 45 08 ff 70 50 8d 85 ?? ff ff ff 50 e8 } //1
		$a_01_1 = {8b 4d 08 89 41 50 c7 45 fc 0b 00 00 00 8b 45 08 c7 40 40 04 00 00 00 c7 45 fc 0c 00 00 00 8b 45 08 c7 40 34 39 05 00 00 c7 45 fc 0e 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}