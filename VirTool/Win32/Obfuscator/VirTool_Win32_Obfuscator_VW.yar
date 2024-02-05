
rule VirTool_Win32_Obfuscator_VW{
	meta:
		description = "VirTool:Win32/Obfuscator.VW,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 4c 83 04 03 cb 85 c0 89 0c 86 75 03 89 75 f8 40 83 f8 19 72 ea } //01 00 
		$a_01_1 = {8b 46 38 8b 4e 34 8b 7e 4c 83 c3 68 53 2b c8 51 50 ff d7 } //00 00 
	condition:
		any of ($a_*)
 
}