
rule VirTool_Win32_Obfuscator_HF{
	meta:
		description = "VirTool:Win32/Obfuscator.HF,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {8b f2 83 c6 03 8b 09 8b d6 8b 09 21 da 8b 09 } //01 00 
		$a_02_1 = {8b 09 81 c1 90 01 04 01 d3 51 01 f6 68 90 01 04 c7 85 f4 ff ff ff 21 ff ff ff 8b 5d f8 5b 81 e8 90 01 04 8d 43 5c c1 eb 05 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}