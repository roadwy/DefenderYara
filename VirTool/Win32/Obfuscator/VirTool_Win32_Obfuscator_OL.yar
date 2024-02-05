
rule VirTool_Win32_Obfuscator_OL{
	meta:
		description = "VirTool:Win32/Obfuscator.OL,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b dd 03 5c 24 18 81 c3 00 10 00 00 8b 33 68 } //01 00 
		$a_01_1 = {53 5b 53 5b 53 5b 53 5b 53 5b 53 5b 81 c4 04 00 00 00 52 33 d2 8b 54 24 04 52 23 d0 ba 10 00 00 00 31 54 24 0c 8b 54 24 0c 03 d4 8f 42 08 0b d1 5a 03 64 24 04 c3 } //00 00 
	condition:
		any of ($a_*)
 
}