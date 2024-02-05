
rule VirTool_Win32_Obfuscator_ACF{
	meta:
		description = "VirTool:Win32/Obfuscator.ACF,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {2b d0 2b d0 03 d0 03 d0 d1 c9 d1 c9 d1 c1 d1 c1 ff d0 87 f6 4b 75 b9 50 58 8b d2 60 90 90 48 83 c0 01 8b } //01 00 
		$a_01_1 = {56 90 90 5f d1 c2 d1 ca 68 9b 00 00 00 59 85 c2 c1 c2 02 c1 ca 02 8d } //00 00 
	condition:
		any of ($a_*)
 
}