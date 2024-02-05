
rule VirTool_Win32_Obfuscator_SX{
	meta:
		description = "VirTool:Win32/Obfuscator.SX,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {ff d6 83 c0 19 64 ff 30 58 ff 70 34 58 83 c7 05 83 e8 06 03 d8 } //00 00 
	condition:
		any of ($a_*)
 
}