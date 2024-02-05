
rule VirTool_Win32_Obfuscator_APG{
	meta:
		description = "VirTool:Win32/Obfuscator.APG,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 44 24 90 01 01 3c 90 01 01 75 02 eb 90 0a 1c 00 ff 15 90 01 03 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}