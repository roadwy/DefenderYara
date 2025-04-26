
rule VirTool_Win32_Obfuscator_AEA{
	meta:
		description = "VirTool:Win32/Obfuscator.AEA,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 45 d8 50 8d 45 e8 50 8d 45 e0 50 ff 75 f8 ff 15 ?? ?? 40 00 83 bd c4 f7 ff ff ff 74 [0-10] 6a 0a 68 ?? ?? 40 00 6a 01 68 ?? ?? 40 00 68 01 00 00 80 ff 15 ?? ?? 40 00 81 bd c4 f7 ff ff ?? ?? ?? ?? 76 0b 81 7d dc 0c 75 cd 01 76 02 eb ?? 8b 85 c4 f7 ff ff 40 89 85 c4 f7 ff ff } //1
		$a_00_1 = {a0 09 01 00 0f 8d af 00 00 00 66 c7 85 e0 f7 ff ff 4f 00 66 c7 85 e2 f7 ff ff 6e 00 c7 45 f4 f4 01 00 00 81 7d f4 f4 01 00 00 0f 85 84 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}