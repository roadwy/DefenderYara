
rule VirTool_Win32_Obfuscator_CAQ{
	meta:
		description = "VirTool:Win32/Obfuscator.CAQ,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 "
		
	strings :
		$a_03_0 = {3b fb 75 0f ff 74 ?? ?? 53 ff 15 ?? ?? ?? ?? 89 44 ?? ?? 8b 44 ?? ?? 89 44 ?? ?? 81 44 ?? ?? ?? ?? ?? ?? 8b 44 ?? ?? 8a 0c 38 8b 44 ?? ?? 88 0c 38 83 ff ?? 75 ?? 56 6a 40 ff 74 ?? ?? 50 ff 15 ?? ?? ?? ?? 89 ?? ?? ?? c7 44 24 ?? ?? ?? ?? ?? 8b 44 ?? ?? 03 c0 89 44 ?? ?? 47 3b 7c 24 ?? 72 } //4
		$a_03_1 = {8a 44 0f 03 8a d0 80 e2 ?? c0 e2 ?? 0a 54 0f ?? 88 55 ?? 8a d0 24 ?? c0 e0 ?? 0a 04 0f c0 e2 ?? 0a 54 0f ?? 88 04 1e 8a 45 ?? 46 88 04 1e 8b 45 ?? 46 88 14 1e 83 c1 ?? 46 3b 08 72 } //4
		$a_03_2 = {8a 44 0f 03 8a d0 80 e2 ?? c0 e2 ?? 0a 54 0f ?? 88 55 ?? 8a d0 24 ?? c0 e0 ?? 0a 04 0f c0 e2 ?? 0a 54 0f ?? 88 04 1e 8a 45 ?? 88 44 1e ?? 8b 45 ?? 88 54 1e ?? 83 c1 ?? 83 c6 ?? 3b 08 72 } //4
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*4+(#a_03_2  & 1)*4) >=8
 
}