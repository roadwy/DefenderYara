
rule VirTool_Win32_Obfuscator_APZ{
	meta:
		description = "VirTool:Win32/Obfuscator.APZ,SIGNATURE_TYPE_PEHSTR_EXT,06 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 4d 10 8b c9 8b 65 08 8b c9 8b 6d 0c ff e1 8b e5 5d c2 0c 00 } //01 00 
	condition:
		any of ($a_*)
 
}