
rule VirTool_Win32_Obfuscator_KX{
	meta:
		description = "VirTool:Win32/Obfuscator.KX,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 76 78 0b f6 74 32 03 f3 8b 76 0c 03 f3 81 3e 4b 45 52 4e 75 23 83 c6 04 } //01 00 
		$a_01_1 = {ad 8b f8 ad 8b c8 83 f8 08 7e 2a 29 4d cc 83 e9 08 d1 e9 33 c0 66 ad 8b d0 c1 ea 0c } //00 00 
	condition:
		any of ($a_*)
 
}