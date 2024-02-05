
rule VirTool_Win32_Obfuscator_BZM{
	meta:
		description = "VirTool:Win32/Obfuscator.BZM,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b ec 8b d5 66 81 fa 01 ff 76 f2 } //01 00 
		$a_03_1 = {3d 00 00 09 00 0f 87 90 01 01 00 00 00 ba 90 01 04 3b c2 0f 87 90 01 01 00 00 00 cc 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}