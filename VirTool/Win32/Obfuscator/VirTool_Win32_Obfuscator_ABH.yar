
rule VirTool_Win32_Obfuscator_ABH{
	meta:
		description = "VirTool:Win32/Obfuscator.ABH,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {83 c0 01 89 45 fc 81 7d fc 10 1e 05 00 0f 83 8d 00 00 00 8b 4d f4 8b 55 f0 8d 44 0a 4f 89 45 f8 8b 4d f4 83 c1 4c 81 f9 e9 01 00 00 76 19 } //2
		$a_01_1 = {8b 02 05 6e 50 00 00 89 45 e0 8b 4d e4 83 c1 4c 8b 55 e8 81 e2 ff 00 00 00 2b ca 66 89 0d } //1
		$a_03_2 = {c7 45 f4 dd 01 00 00 c6 45 fc 00 33 c0 66 89 45 fd c7 45 e8 c9 00 00 00 33 c9 8a 0d 90 01 02 42 00 83 c1 63 39 4d f8 74 1a 90 00 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_03_2  & 1)*2) >=3
 
}