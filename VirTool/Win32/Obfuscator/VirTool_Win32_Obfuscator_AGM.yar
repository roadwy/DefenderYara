
rule VirTool_Win32_Obfuscator_AGM{
	meta:
		description = "VirTool:Win32/Obfuscator.AGM,SIGNATURE_TYPE_PEHSTR_EXT,05 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c2 8b c7 2b c6 51 5a e2 f6 61 81 (bd|7d) [0-04] ?? ?? 00 00 74 03 83 ef 04 e2 } //1
		$a_03_1 = {33 d2 f7 e3 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? ad 33 05 ?? ?? ?? ?? 89 (45|85) [0-04] a1 ?? ?? ?? ?? bb ?? ?? ?? ?? 33 d2 f7 e3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}