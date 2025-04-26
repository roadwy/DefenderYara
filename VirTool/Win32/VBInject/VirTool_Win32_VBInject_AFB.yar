
rule VirTool_Win32_VBInject_AFB{
	meta:
		description = "VirTool:Win32/VBInject.AFB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 c4 0c be 74 23 11 00 c7 43 34 04 00 00 00 8b 43 34 3b c6 89 85 50 fe ff ff 0f 8f 05 01 00 00 } //1
		$a_03_1 = {8b 48 54 c7 81 ?? ?? 00 00 ae 92 76 a8 8b 48 54 c7 81 ?? ?? 00 00 f0 c3 61 93 8b 48 54 c7 81 ?? ?? 00 00 93 16 1d 43 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}