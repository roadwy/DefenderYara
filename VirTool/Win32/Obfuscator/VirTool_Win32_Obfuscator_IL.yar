
rule VirTool_Win32_Obfuscator_IL{
	meta:
		description = "VirTool:Win32/Obfuscator.IL,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {a1 e8 02 fe 7f 90 02 08 0b c0 90 13 6a 1c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}