
rule VirTool_Win32_Obfuscator_ZO{
	meta:
		description = "VirTool:Win32/Obfuscator.ZO,SIGNATURE_TYPE_PEHSTR_EXT,05 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 85 54 fd ff ff bb 0d 66 19 00 33 d2 f7 e3 05 5f f3 6e 3c 89 85 54 fd ff ff ad 33 85 54 fd ff ff ab e2 dc b8 00 24 00 00 bb 04 00 00 00 33 d2 f7 f3 } //1
		$a_03_1 = {c1 e3 10 b9 ff ff 00 00 53 e8 ?? ?? ?? ?? 3d ?? ?? ?? ?? 75 06 89 9d 54 fd ff ff 43 e2 ea 61 83 bd 54 fd ff ff 00 0f 84 aa 00 00 00 b9 00 24 00 00 c1 e9 02 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}