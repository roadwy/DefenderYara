
rule VirTool_Win32_Obfuscator_WG{
	meta:
		description = "VirTool:Win32/Obfuscator.WG,SIGNATURE_TYPE_PEHSTR,06 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 14 03 45 f4 0f b6 08 89 4d f0 8b 55 f4 03 55 d0 89 55 f4 c7 45 c8 01 00 00 00 8b 45 f4 33 d2 f7 75 fc b9 01 00 00 00 2b c8 89 4d c8 } //1
		$a_01_1 = {8b 45 ec 03 45 f8 0f b6 08 03 4d f0 88 4d c7 8b 55 ec 03 55 f8 8a 45 c7 88 02 8b 4d f8 83 c1 02 89 4d f8 e9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}