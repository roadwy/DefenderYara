
rule VirTool_Win32_Obfuscator_BZC{
	meta:
		description = "VirTool:Win32/Obfuscator.BZC,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {4d 74 21 33 c0 05 00 00 00 00 8a 88 ?? ?? ?? ?? 80 f1 ?? 80 e9 ?? 88 88 ?? ?? ?? ?? 40 3d 00 2c 00 00 72 90 09 06 00 80 3d } //1
		$a_03_1 = {33 d2 b8 49 00 00 00 f7 f1 ba 2e 06 00 00 2b d0 b8 4d 5a 00 00 89 15 ?? ?? ?? ?? 66 39 45 00 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}