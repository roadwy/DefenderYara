
rule VirTool_Win32_Obfuscator_OE{
	meta:
		description = "VirTool:Win32/Obfuscator.OE,SIGNATURE_TYPE_PEHSTR_EXT,03 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff 45 70 8b 45 70 8b 4d 68 3b c1 0f 82 90 01 01 ff ff ff 8b 45 d8 8b 4d 70 3b c8 0f 85 90 01 02 00 00 90 00 } //01 00 
		$a_01_1 = {c6 45 40 7f c6 45 41 67 c6 45 42 43 88 5d 43 c7 45 68 00 20 00 00 89 5d 70 8b f7 } //00 00 
	condition:
		any of ($a_*)
 
}