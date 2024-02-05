
rule VirTool_Win32_Obfuscator_AEZ{
	meta:
		description = "VirTool:Win32/Obfuscator.AEZ,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {73 15 66 8b 46 90 01 01 86 e0 66 89 46 90 1b 00 83 c6 90 01 01 83 c3 90 1b 02 e8 e2 ff ff ff 90 09 07 00 58 3b 9a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}