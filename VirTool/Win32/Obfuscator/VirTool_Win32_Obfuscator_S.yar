
rule VirTool_Win32_Obfuscator_S{
	meta:
		description = "VirTool:Win32/Obfuscator.S,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {66 33 f6 66 81 3e 4d 5a 75 f5 89 75 00 be 00 00 90 01 02 2b 75 00 89 75 20 c7 45 24 90 01 04 c7 45 28 90 01 04 33 c0 64 8b 40 30 8b 40 0c 8b 40 1c ff 70 08 8f 45 08 90 00 } //01 00 
		$a_02_1 = {66 33 f6 66 81 3e 4d 5a 75 f5 89 75 00 be 00 00 90 01 02 2b 75 00 89 75 1c c7 45 20 90 01 04 c7 45 24 90 01 04 33 c0 64 8b 78 20 64 8b 40 30 8b 40 0c 8b 40 1c ff 70 08 8f 45 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}