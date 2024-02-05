
rule VirTool_Win32_Obfuscator_QK{
	meta:
		description = "VirTool:Win32/Obfuscator.QK,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {b8 01 00 00 00 c3 8b 65 e8 } //01 00 
		$a_03_1 = {6a 40 68 00 30 00 00 68 58 04 00 00 6a 00 ff 55 90 01 01 89 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}