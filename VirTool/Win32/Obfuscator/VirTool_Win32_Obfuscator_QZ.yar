
rule VirTool_Win32_Obfuscator_QZ{
	meta:
		description = "VirTool:Win32/Obfuscator.QZ,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_00_0 = {89 85 40 ff ff ff eb 0a c7 85 40 ff ff ff 03 00 00 00 8b 8d 40 ff ff ff c1 e1 06 8b 55 e8 8d 84 4a 60 03 00 00 89 45 a8 c7 45 80 01 00 00 00 } //1
		$a_02_1 = {8b 55 24 8b e2 68 00 80 00 00 2d 07 03 00 00 6a 00 2b c1 ff 75 20 05 41 01 00 00 ff 75 ?? 8b 45 10 8b ?? ff e0 } //1
		$a_00_2 = {42 65 65 70 00 00 b8 01 48 65 61 70 41 6c 6c 6f 63 00 59 01 47 65 74 50 72 6f 63 65 73 73 48 65 61 70 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=1
 
}