
rule VirTool_Win32_Obfuscator_AOD{
	meta:
		description = "VirTool:Win32/Obfuscator.AOD,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {32 d1 80 fa f2 88 94 35 90 01 02 ff ff 77 90 01 01 fe ca 88 94 35 90 01 02 ff ff 46 90 00 } //01 00 
		$a_03_1 = {df e0 f6 c4 41 75 90 01 01 68 90 01 04 6a 00 8d 8d 90 01 02 ff ff ff d1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}