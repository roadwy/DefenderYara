
rule VirTool_Win32_Obfuscator_AHY{
	meta:
		description = "VirTool:Win32/Obfuscator.AHY,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {20 a8 5a 2a b2 66 20 03 be 22 f5 61 66 65 20 7c 1b f7 b8 } //1
		$a_01_1 = {20 60 18 48 e6 66 66 20 bb e7 b7 19 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule VirTool_Win32_Obfuscator_AHY_2{
	meta:
		description = "VirTool:Win32/Obfuscator.AHY,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {c7 05 80 05 41 00 ?? ?? 40 00 89 1d 84 05 41 00 c7 05 88 05 41 00 ?? ?? 40 00 c7 05 8c 05 41 00 ?? ?? 40 00 c7 05 90 90 05 41 00 ?? ?? 40 00 c7 05 94 05 41 00 ?? ?? 40 00 c7 05 98 05 41 00 ?? ?? 40 00 c7 05 9c 05 41 00 ?? ?? 40 00 ?? ?? 00 00 00 64 8b 1d 18 00 00 00 89 1d 70 05 41 00 a1 2c 0e 41 00 8b 0d 00 f0 40 00 33 f6 89 0d ac 05 41 00 3b c6 75 20 8b 15 9c 05 41 00 6a 40 68 00 30 00 00 8b 42 14 83 c0 10 50 56 ff 15 08 f0 40 00 a3 2c 0e 41 00 } //1
		$a_02_1 = {8b 15 2c 0e 41 00 89 35 64 05 41 00 89 35 68 05 41 00 89 15 68 b1 41 00 e8 ?? ?? ?? ?? 68 78 05 41 00 ff 15 2c 0e 41 00 } //1
		$a_01_2 = {8b ce 8b 1d 48 0e 41 00 2b c8 8a 09 c6 05 ac 0e 41 00 00 88 0d 1c 0e 41 00 8b 0d 1c 0e 41 00 81 e1 ff 00 00 00 d3 e3 89 1d 48 0e 41 00 33 db 8a 1c 30 2b cb 8b 1d 48 0e 41 00 d3 eb 83 f9 0b 89 0d 68 05 41 00 89 1d 48 0e 41 00 75 44 8b 15 70 05 41 00 6a 00 89 aa 00 10 00 00 a1 70 05 41 00 8b 0d 48 0e 41 00 8b 80 04 10 00 00 41 a3 70 05 41 00 89 0d 48 0e 41 00 89 a8 00 10 00 00 ff d7 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}