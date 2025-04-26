
rule VirTool_Win32_Obfuscator_BF{
	meta:
		description = "VirTool:Win32/Obfuscator.BF,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 ff 24 01 b8 ?? ?? ?? ?? 33 c9 bb ?? ?? 40 00 81 ff 06 27 00 00 75 02 28 03 43 c1 e8 08 41 83 f9 04 75 0a b8 ?? ?? ?? ?? b9 00 00 00 00 81 fb ?? ?? 40 00 72 da 47 81 ff 11 27 00 00 76 c5 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}