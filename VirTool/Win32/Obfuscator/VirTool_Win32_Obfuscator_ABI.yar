
rule VirTool_Win32_Obfuscator_ABI{
	meta:
		description = "VirTool:Win32/Obfuscator.ABI,SIGNATURE_TYPE_PEHSTR_EXT,64 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f af d0 8b 45 e4 23 d0 c0 4d ff 04 89 55 d0 8b 45 c8 8a 55 ff 88 10 8b 45 f8 40 89 45 f8 3b 45 f4 0f 82 } //00 00 
	condition:
		any of ($a_*)
 
}