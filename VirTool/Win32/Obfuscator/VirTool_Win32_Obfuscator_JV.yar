
rule VirTool_Win32_Obfuscator_JV{
	meta:
		description = "VirTool:Win32/Obfuscator.JV,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 40 05 67 c6 40 02 74 c6 00 47 c6 40 03 52 c6 40 04 65 c6 40 01 65 } //00 00 
	condition:
		any of ($a_*)
 
}