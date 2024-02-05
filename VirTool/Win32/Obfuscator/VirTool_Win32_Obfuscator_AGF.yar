
rule VirTool_Win32_Obfuscator_AGF{
	meta:
		description = "VirTool:Win32/Obfuscator.AGF,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 57 4c 4f 53 44 00 } //01 00 
		$a_01_1 = {8a 10 83 ea 12 88 10 40 39 c8 75 } //01 00 
		$a_01_2 = {83 ec 10 8b 15 0c 50 40 00 42 89 15 0c 50 40 00 39 d3 7f } //00 00 
	condition:
		any of ($a_*)
 
}