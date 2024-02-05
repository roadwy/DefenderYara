
rule VirTool_Win32_Obfuscator_ABF{
	meta:
		description = "VirTool:Win32/Obfuscator.ABF,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {80 b2 e6 0e 73 15 8b 90 01 02 0f af 90 01 02 89 90 01 02 8b 90 01 02 83 90 01 02 89 90 01 02 eb d9 90 00 } //01 00 
		$a_03_1 = {83 c4 04 69 c0 90 01 01 90 04 01 02 6d 6e 00 00 50 68 90 01 02 40 00 8b 90 01 01 08 d1 90 04 01 03 e0 e1 e2 d1 90 04 01 03 e8 e9 ea 90 04 01 03 50 51 52 ff 55 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}