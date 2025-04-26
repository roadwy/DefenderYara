
rule VirTool_Win32_Obfuscator_BD{
	meta:
		description = "VirTool:Win32/Obfuscator.BD,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {eb 00 33 d2 b8 ?? ?? ?? ?? 33 c9 bb ?? ?? ?? ?? 81 fa ac 26 00 00 75 02 28 03 43 c1 e8 08 41 83 f9 04 75 0a b8 ?? ?? ?? ?? b9 00 00 00 00 81 fb ?? ?? ?? ?? 72 da 42 81 fa 1b 27 00 00 76 c5 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}