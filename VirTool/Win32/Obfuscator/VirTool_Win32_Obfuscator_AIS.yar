
rule VirTool_Win32_Obfuscator_AIS{
	meta:
		description = "VirTool:Win32/Obfuscator.AIS,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {64 a1 10 00 00 00 8b 46 50 8d 55 f8 52 6a 40 50 53 ff d7 8b 4e 50 6a 40 68 00 10 00 00 51 6a 00 ff 15 ?? ?? ?? ?? 8b 4e 50 8b d1 c1 e9 02 8b f8 8b f3 f3 a5 8b ca 83 e1 03 50 89 45 08 f3 a4 e8 ?? ?? ff ff 8b 45 10 8b 4d f4 50 8b 45 08 ba ?? ?? ?? ?? 51 2b d3 50 03 d0 ff d2 } //1
		$a_03_1 = {6a 00 6a 00 68 00 04 00 00 ff 15 ?? ?? ?? ?? e8 ?? ?? ff ff 85 c0 75 13 8b 44 24 78 50 ff 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b f0 68 03 01 00 00 8d 8c 24 80 00 00 00 57 51 e8 ?? ?? 00 00 57 8d 94 24 8c 00 00 00 68 ?? ?? ?? ?? 52 89 2e ff d3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}