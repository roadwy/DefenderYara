
rule VirTool_Win32_Obfuscator_BU{
	meta:
		description = "VirTool:Win32/Obfuscator.BU,SIGNATURE_TYPE_PEHSTR_EXT,15 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {4c 6f 61 64 c7 45 ?? 4c 69 62 72 c7 45 ?? 61 72 79 41 c7 45 ?? 00 00 00 00 c7 45 ?? 56 69 72 74 c7 45 ?? 75 61 6c 50 c7 45 ?? 72 6f 74 65 c7 45 ?? 63 74 00 00 c7 45 ?? 56 69 72 74 c7 45 ?? 75 61 6c 41 c7 45 ?? 6c 6c 6f 63 } //10
		$a_02_1 = {e8 00 00 00 00 58 8b f0 2d ?? ?? ?? ?? 89 ?? ?? ff ff ff 81 ?? 00 f0 ff ff 89 ?? ?? ff ff ff 8b ?? ?? 81 ?? 00 f0 ff ff 66 ?? ?? 4d 5a 74 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}