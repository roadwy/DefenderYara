
rule VirTool_Win32_Obfuscator_KV{
	meta:
		description = "VirTool:Win32/Obfuscator.KV,SIGNATURE_TYPE_PEHSTR_EXT,64 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 04 6a 02 90 01 01 ff 15 90 01 04 83 c4 10 8b 45 f0 2d 90 01 04 89 45 f0 85 c0 0f 85 90 01 02 ff ff ff 15 90 01 04 83 f8 7e 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}