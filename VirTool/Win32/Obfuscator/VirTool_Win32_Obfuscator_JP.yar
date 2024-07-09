
rule VirTool_Win32_Obfuscator_JP{
	meta:
		description = "VirTool:Win32/Obfuscator.JP,SIGNATURE_TYPE_PEHSTR_EXT,06 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {58 fe ff ff 89 ?? f0 [0-04] 00 89 ?? d8 8b ?? f0 83 [0-02] 89 ?? e4 81 75 fc 38 00 00 00 } //1
		$a_01_1 = {c7 45 e0 00 00 40 00 83 65 e8 00 83 a5 54 fe ff ff 00 eb } //1
		$a_03_2 = {6a 18 66 89 45 ?? 58 6a 06 66 89 45 ?? 59 33 c0 8d 7d ?? f3 ab 8b 45 ?? 0f af 45 ?? 6b c0 03 } //1
		$a_03_3 = {24 83 c4 04 29 ?? 8b ?? 08 03 ?? f8 c6 ?? 00 30 ?? 8b ?? fc ?? 89 ?? fc 83 7d fc 01 75 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*2) >=3
 
}