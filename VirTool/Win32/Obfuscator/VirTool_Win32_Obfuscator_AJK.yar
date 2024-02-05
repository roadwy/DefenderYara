
rule VirTool_Win32_Obfuscator_AJK{
	meta:
		description = "VirTool:Win32/Obfuscator.AJK,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {b9 a4 01 00 00 bb 90 01 04 31 1e 81 eb 90 01 04 a5 e2 f5 83 c0 06 ff d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}