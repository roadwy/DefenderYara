
rule VirTool_Win32_Obfuscator_UJ{
	meta:
		description = "VirTool:Win32/Obfuscator.UJ,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {c2 7f b8 40 00 00 00 e8 90 09 16 00 8d 0d 90 01 04 89 4d f8 83 6d f8 78 8b 15 90 01 04 8b 12 83 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}