
rule VirTool_Win32_Obfuscator_AYA{
	meta:
		description = "VirTool:Win32/Obfuscator.AYA,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {8b c0 83 c2 01 8b c0 a1 90 01 04 8b c0 8b ca 8b c0 8b d0 33 d1 8b c2 c7 05 90 01 04 00 00 00 00 01 05 90 01 04 8b 0d 90 01 04 8b 15 90 01 04 89 11 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}