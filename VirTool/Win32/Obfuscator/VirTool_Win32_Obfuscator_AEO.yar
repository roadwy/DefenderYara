
rule VirTool_Win32_Obfuscator_AEO{
	meta:
		description = "VirTool:Win32/Obfuscator.AEO,SIGNATURE_TYPE_PEHSTR_EXT,04 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {55 53 ff 35 90 90 d4 40 00 68 90 01 02 40 00 e8 41 11 00 00 8b 2d 50 ae 40 00 8d 45 00 50 e8 f3 68 00 00 ff 35 90 90 d4 40 00 68 90 01 02 40 00 90 00 } //01 00 
		$a_01_1 = {68 26 72 34 3b 68 c4 79 51 fb e8 1f 23 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}