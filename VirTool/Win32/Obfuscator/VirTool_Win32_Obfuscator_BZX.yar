
rule VirTool_Win32_Obfuscator_BZX{
	meta:
		description = "VirTool:Win32/Obfuscator.BZX,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c6 85 1c ff ff ff 56 c6 85 1d ff ff ff 69 c6 85 1e ff ff ff 72 c6 85 1f ff ff ff 74 c6 85 20 ff ff ff 75 c6 85 21 ff ff ff 61 c6 85 22 ff ff ff 6c c6 85 23 ff ff ff 41 c6 85 24 ff ff ff 6c c6 85 25 ff ff ff 6c c6 85 26 ff ff ff 6f c6 85 27 ff ff ff 63 } //1
		$a_01_1 = {ff 55 fc 89 85 c4 fe ff ff 8d 8d 2c ff ff ff 51 8b 55 f8 52 ff 55 fc 89 85 94 fe ff ff 8d 45 9c 50 8b 4d f8 51 ff 55 fc 89 85 c4 fe ff ff 8d 95 48 ff ff ff 52 8b 45 f8 50 ff 55 fc } //1
		$a_01_2 = {58 ff d0 6a 00 ff 95 7c fe ff ff 8b e5 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}