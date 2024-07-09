
rule VirTool_Win32_VBInject_AFA{
	meta:
		description = "VirTool:Win32/VBInject.AFA,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c7 46 34 04 00 00 00 8b 46 34 b9 74 23 11 00 3b c1 89 85 48 fe ff ff 0f 8f 05 01 00 00 dd 05 e8 10 40 00 8b 0e d9 e1 df e0 a8 0d 0f 85 ab 02 00 00 } //1
		$a_03_1 = {8b 48 54 c7 81 ?? ?? 00 00 66 0f 66 e8 8b 48 54 c7 81 ?? ?? 00 00 b2 40 40 24 8b 48 54 c7 81 ?? ?? 00 00 6d 47 40 cf } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}