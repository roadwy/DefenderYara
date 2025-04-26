
rule VirTool_Win32_Obfuscator_VA{
	meta:
		description = "VirTool:Win32/Obfuscator.VA,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {83 f8 00 83 e8 2d ff e0 cc cc cc cc cc } //1
		$a_01_1 = {8b 95 f0 fd ff ff 8a 0c 4a 88 8c 28 e0 fc ff ff } //1
		$a_00_2 = {68 65 6c 70 2e 64 6c 6c } //1 help.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1) >=2
 
}
rule VirTool_Win32_Obfuscator_VA_2{
	meta:
		description = "VirTool:Win32/Obfuscator.VA,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {dc 00 00 40 8b 0d ?? ?? 01 01 89 01 a1 ?? 3b 01 01 2b 05 ?? 44 01 01 85 c0 74 0f } //1
		$a_01_1 = {01 01 0f 86 1e 02 00 00 83 65 ec 00 83 7d e8 ff 75 1d e8 } //1
		$a_03_2 = {3b 01 01 0f b6 49 10 89 04 8d ?? ?? 01 01 a1 ?? 3b 01 01 40 a3 ?? 3b 01 01 eb a0 } //1
		$a_03_3 = {3b 01 01 88 01 a1 ?? 3b 01 01 25 f0 01 00 00 a3 ?? 3b 01 01 e9 ?? fe ff ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}