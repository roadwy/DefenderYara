
rule VirTool_Win32_Obfuscator_DR{
	meta:
		description = "VirTool:Win32/Obfuscator.DR,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {e8 00 00 00 00 58 25 00 00 ff ff 66 8b 00 66 35 de c0 66 3d 93 9a 74 07 2d 00 00 01 00 eb e7 25 00 00 ff ff 89 45 fc 8b 45 fc } //01 00 
	condition:
		any of ($a_*)
 
}