
rule VirTool_Win32_Obfuscator_AAI{
	meta:
		description = "VirTool:Win32/Obfuscator.AAI,SIGNATURE_TYPE_PEHSTR_EXT,03 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {83 f1 40 51 b9 00 20 00 00 81 e9 00 f0 ff ff 51 c1 e6 02 56 } //01 00 
		$a_03_1 = {8a 1c 06 42 2a 9a 90 01 04 80 24 37 00 88 1c 37 83 ea 01 74 04 39 c0 74 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}