
rule VirTool_Win64_Obfuscator_G{
	meta:
		description = "VirTool:Win64/Obfuscator.G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 33 c0 65 48 03 40 60 c3 } //01 00 
		$a_01_1 = {48 8b e1 48 8b c2 4c 8b 4c 24 20 48 8b 54 24 10 48 8b 4c 24 08 4c 8b 44 24 18 ff e0 } //00 00 
	condition:
		any of ($a_*)
 
}