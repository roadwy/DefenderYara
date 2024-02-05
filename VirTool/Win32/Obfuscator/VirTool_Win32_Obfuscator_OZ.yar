
rule VirTool_Win32_Obfuscator_OZ{
	meta:
		description = "VirTool:Win32/Obfuscator.OZ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {83 64 24 14 00 66 83 bc 24 c0 00 00 00 00 74 50 33 f6 8d bc 24 c0 00 00 00 68 00 02 00 00 53 ff 15 90 01 04 6a 01 8d 86 90 01 04 50 57 ff 15 90 01 04 85 c0 0f 85 90 01 04 68 90 01 04 50 ff 15 90 01 04 ff 44 24 14 8b 74 24 14 03 f6 8d bc 34 c0 00 00 00 66 83 3f 00 75 b9 8d 44 24 78 50 6a 00 68 90 01 04 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}