
rule VirTool_BAT_Obfuscator_X{
	meta:
		description = "VirTool:BAT/Obfuscator.X,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 90 01 01 19 4a 00 61 00 76 00 61 00 20 00 55 00 70 00 64 00 61 00 74 00 65 00 72 00 90 00 } //01 00 
		$a_00_1 = {63 00 68 00 65 00 65 00 73 00 65 00 } //01 00  cheese
		$a_00_2 = {73 00 68 00 61 00 6e 00 6b 00 } //00 00  shank
	condition:
		any of ($a_*)
 
}