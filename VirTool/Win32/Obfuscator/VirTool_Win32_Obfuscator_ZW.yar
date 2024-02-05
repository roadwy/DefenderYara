
rule VirTool_Win32_Obfuscator_ZW{
	meta:
		description = "VirTool:Win32/Obfuscator.ZW,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {64 5c 74 65 73 74 31 32 33 5c 90 04 04 03 30 2d 39 5c 52 65 6c 65 61 73 65 5c 90 04 04 03 30 2d 39 2e 70 64 62 90 09 0a 00 90 03 01 01 64 65 3a 5c 44 6f 77 6e 6c 6f 61 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}