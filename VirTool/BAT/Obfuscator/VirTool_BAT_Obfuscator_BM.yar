
rule VirTool_BAT_Obfuscator_BM{
	meta:
		description = "VirTool:BAT/Obfuscator.BM,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 75 73 65 72 33 32 2e 64 6c 6c 00 90 02 10 26 00 43 6f 6e 73 6f 6c 65 41 70 70 6c 69 63 61 74 69 6f 6e 42 61 73 65 90 00 } //01 00 
		$a_00_1 = {5f 00 45 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 24 00 } //00 00  _Encrypted$
	condition:
		any of ($a_*)
 
}