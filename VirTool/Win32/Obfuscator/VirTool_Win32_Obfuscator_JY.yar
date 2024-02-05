
rule VirTool_Win32_Obfuscator_JY{
	meta:
		description = "VirTool:Win32/Obfuscator.JY,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {a9 8b 08 00 90 09 06 00 c7 85 90 01 02 ff ff 90 08 00 02 83 bd 90 1b 01 ff ff 00 0f 84 90 01 02 00 00 90 02 ff c7 85 90 01 02 ff ff 90 01 02 00 00 90 08 00 02 ff b5 90 1b 06 ff ff 68 90 1b 07 00 00 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}