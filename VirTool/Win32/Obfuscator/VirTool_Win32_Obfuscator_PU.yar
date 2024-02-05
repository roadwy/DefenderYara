
rule VirTool_Win32_Obfuscator_PU{
	meta:
		description = "VirTool:Win32/Obfuscator.PU,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {87 ec 8d 6d fc 89 65 00 8d 65 } //01 00 
		$a_03_1 = {81 14 24 89 0a 00 00 90 02 04 ba fd a5 17 90 02 04 81 14 24 5e 34 9a e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}