
rule VirTool_Win32_Obfuscator_ADX{
	meta:
		description = "VirTool:Win32/Obfuscator.ADX,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {81 8f c0 00 00 00 00 01 00 00 e9 16 00 00 00 c7 46 1c c2 00 00 00 81 a7 c0 00 00 00 ff fe ff ff } //01 00 
		$a_03_1 = {0f b6 03 3c eb 0f 85 1c 00 00 00 0f b6 43 01 0f ba f0 07 0f 83 05 00 00 00 90 03 05 05 2d 80 00 00 00 05 80 ff ff ff 8d 44 03 02 90 00 } //00 00 
		$a_00_2 = {78 } //b9 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Obfuscator_ADX_2{
	meta:
		description = "VirTool:Win32/Obfuscator.ADX,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {ac 8b da c1 eb 18 32 c3 aa eb 0a 8b fd 03 f9 8b f7 ac 32 c1 aa 41 81 f9 90 01 03 00 72 02 90 00 } //01 00 
		$a_03_1 = {8b d6 8b fd 03 f9 8b f7 ac 8b da c1 eb 18 32 c3 aa 41 81 90 01 04 00 72 02 ff e5 90 00 } //02 00 
		$a_03_2 = {8b fb f3 a5 2d 90 01 01 07 00 00 2c 90 01 01 33 c9 66 a5 d0 e0 30 04 19 41 83 f9 90 01 01 7c f7 90 09 0a 00 b9 90 01 01 00 00 00 be 90 00 } //02 00 
		$a_01_3 = {8b 78 04 0f b6 18 0f b7 ca 66 0f be 3c 0f 66 33 fb 66 33 fa bb ff 00 00 00 66 23 fb 42 66 89 3c 4e 66 3b 50 02 72 d9 5f 5b 0f b7 40 02 33 c9 66 89 0c 46 } //00 00 
		$a_00_4 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}