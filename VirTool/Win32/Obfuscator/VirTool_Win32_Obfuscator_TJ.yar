
rule VirTool_Win32_Obfuscator_TJ{
	meta:
		description = "VirTool:Win32/Obfuscator.TJ,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {83 c7 04 c7 07 90 01 04 83 c7 04 c7 07 90 01 04 83 c7 04 c7 07 90 01 04 83 c7 04 c7 07 90 01 04 83 c7 04 c7 07 90 01 04 83 c7 04 90 00 } //01 00 
		$a_02_1 = {55 8b ec 83 ec 20 53 56 57 e8 90 01 01 ee ff ff 33 db 39 1d f8 a2 41 00 89 45 f8 89 5d fc 89 5d f4 89 5d f0 90 00 } //01 00 
		$a_02_2 = {8b 74 24 08 85 f6 0f 84 81 01 00 00 ff 76 04 e8 90 01 01 dd ff ff ff 76 08 e8 90 01 01 dd ff ff ff 76 0c e8 90 01 01 dd ff ff ff 76 10 e8 90 00 } //01 00 
		$a_11_3 = {33 64 38 00 75 73 65 72 33 32 00 6e 74 64 6c 6c 00 } //00 5d 
	condition:
		any of ($a_*)
 
}