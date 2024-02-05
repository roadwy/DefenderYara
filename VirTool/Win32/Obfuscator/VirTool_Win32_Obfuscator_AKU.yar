
rule VirTool_Win32_Obfuscator_AKU{
	meta:
		description = "VirTool:Win32/Obfuscator.AKU,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 89 c7 31 c7 89 f8 5f 8b 00 8b 64 24 08 64 8f 05 00 00 00 00 58 5b } //01 00 
		$a_01_1 = {c7 04 24 01 00 00 00 59 d3 c0 8a dc b4 00 d3 cb 59 49 75 ea } //01 00 
		$a_01_2 = {30 14 39 49 75 fa } //01 00 
		$a_01_3 = {31 04 24 58 } //00 00 
	condition:
		any of ($a_*)
 
}