
rule VirTool_Win32_Obfuscator_IG{
	meta:
		description = "VirTool:Win32/Obfuscator.IG,SIGNATURE_TYPE_PEHSTR_EXT,04 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {c7 07 d3 ca b9 ?? c7 47 04 ?? ?? ?? ad c7 47 08 33 c2 d3 c2 c7 47 0c ab e2 f8 ff c6 47 10 e3 } //1
		$a_03_1 = {ad 33 c2 d3 c2 ab e2 f8 ff ?? ?? ?? ?? ?? c3 (90 09 16 00 d3 ca b9|90 09 15 00 d3 ca 66 b9) } //1
		$a_01_2 = {c7 07 ad 33 c2 d3 c7 47 04 c2 ab e2 f8 66 c7 47 08 ff e3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}