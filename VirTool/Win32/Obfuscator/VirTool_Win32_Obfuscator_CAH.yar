
rule VirTool_Win32_Obfuscator_CAH{
	meta:
		description = "VirTool:Win32/Obfuscator.CAH,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 85 cc fe ff ff 83 bd cc fe ff ff 06 75 24 dd 05 ?? ?? 41 00 e8 ?? ?? 00 00 d9 9d c4 fe ff ff d9 85 c4 fe ff ff dc 1d ?? ?? 41 00 df e0 f6 c4 41 75 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-06] ff b5 cc fe ff ff e8 ?? ?? ff ff 83 c4 10 89 45 f0 e9 ?? ff ff ff ff 75 ec ff 15 ?? ?? 41 00 59 6a 00 ff 15 ?? ?? 41 00 83 f8 65 75 20 e8 ?? ?? ff ff 85 c0 } //1
		$a_03_1 = {57 0f 31 8b ff 89 55 f4 8b ff 89 45 f0 8b ff ff 15 ?? ?? ?? 00 0f 31 8b ff 89 55 fc 8b ff 89 45 f8 8b ff 8b 45 f8 2b 45 f0 8b 4d fc 1b 4d f4 5f c9 c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}