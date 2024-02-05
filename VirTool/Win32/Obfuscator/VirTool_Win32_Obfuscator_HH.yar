
rule VirTool_Win32_Obfuscator_HH{
	meta:
		description = "VirTool:Win32/Obfuscator.HH,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 5d ec 8b 3f 83 ee ae 2b d3 c1 e7 08 03 75 f4 8b ce 81 c7 90 01 04 b9 04 00 00 00 01 f6 b9 90 01 04 01 de 39 89 a4 00 00 00 74 ef 8b ca 57 68 90 01 04 be 51 ff ff ff 2b 75 f0 5a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}