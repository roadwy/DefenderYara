
rule VirTool_Win32_Obfuscator_AOT{
	meta:
		description = "VirTool:Win32/Obfuscator.AOT,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {2b 4d f8 81 c1 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? 0f b6 15 } //1
		$a_03_1 = {03 55 f8 81 ea ?? ?? ?? ?? 88 15 ?? ?? ?? ?? 0f b6 05 ?? ?? ?? ?? 03 45 f8 } //1
		$a_03_2 = {2b 45 f8 05 ?? ?? ?? ?? a2 ?? ?? ?? ?? c6 05 ?? ?? ?? ?? ?? 0f b6 0d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}
rule VirTool_Win32_Obfuscator_AOT_2{
	meta:
		description = "VirTool:Win32/Obfuscator.AOT,SIGNATURE_TYPE_PEHSTR_EXT,06 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {85 d2 74 01 46 49 75 f8 [0-14] 8b 1d ?? ?? [40-47] 00 50 52 ff d3 } //1
		$a_01_1 = {85 f6 74 01 42 49 75 f8 f8 [0-14] 8b 1d ?? ?? [40-47] 00 50 56 ff d7 } //1
		$a_03_2 = {7e 07 03 f1 41 3b ca 7c f9 [0-30] 81 e2 ff 01 00 00 03 c2 [0-30] ff 15 ?? ?? ?? ?? 50 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}