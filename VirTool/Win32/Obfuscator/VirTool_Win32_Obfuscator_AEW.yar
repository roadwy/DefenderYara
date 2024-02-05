
rule VirTool_Win32_Obfuscator_AEW{
	meta:
		description = "VirTool:Win32/Obfuscator.AEW,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {ff 55 28 89 45 a4 ff 75 a4 ff 55 18 89 45 a4 } //01 00 
		$a_01_1 = {8b 55 08 03 55 eb 8a 45 f7 88 02 8b 55 fc 03 55 ef 89 55 fc } //00 00 
	condition:
		any of ($a_*)
 
}