
rule VirTool_Win32_Obfuscator_IG{
	meta:
		description = "VirTool:Win32/Obfuscator.IG,SIGNATURE_TYPE_PEHSTR_EXT,04 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {c7 07 d3 ca b9 90 01 01 c7 47 04 90 01 03 ad c7 47 08 33 c2 d3 c2 c7 47 0c ab e2 f8 ff c6 47 10 e3 90 00 } //01 00 
		$a_03_1 = {ad 33 c2 d3 c2 ab e2 f8 ff 90 01 05 c3 90 03 07 08 90 09 16 00 d3 ca b9 90 09 15 00 d3 ca 66 b9 90 00 } //01 00 
		$a_01_2 = {c7 07 ad 33 c2 d3 c7 47 04 c2 ab e2 f8 66 c7 47 08 ff e3 } //00 00 
	condition:
		any of ($a_*)
 
}