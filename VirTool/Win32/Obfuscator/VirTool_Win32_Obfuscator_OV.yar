
rule VirTool_Win32_Obfuscator_OV{
	meta:
		description = "VirTool:Win32/Obfuscator.OV,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {57 3e 00 00 90 09 02 00 81 90 05 01 03 c1 2d c7 } //1
		$a_00_1 = {81 ca 79 79 79 79 } //1
		$a_02_2 = {6a 00 6a 01 [0-08] ff 55 ?? 8b ?? 0c 8b ?? ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? ?? 89 ?? ?? 6a 00 8b ?? 08 ?? 6a 00 6a 00 ff 55 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}