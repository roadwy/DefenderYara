
rule VirTool_Win32_Obfuscator_AIX{
	meta:
		description = "VirTool:Win32/Obfuscator.AIX,SIGNATURE_TYPE_PEHSTR_EXT,ffffffe7 03 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 08 33 d2 33 c0 85 c9 76 3b 53 55 8b 6c 24 18 56 8b 74 24 10 57 8b 7c 24 1c 8d 64 24 00 8b ca 83 e1 1f bb 01 00 00 00 d3 e3 85 dd 74 09 8a 0e 88 0f 47 46 40 eb 01 } //1
		$a_01_1 = {33 c0 66 8b 02 8b e8 81 e5 00 f0 00 00 81 fd 00 30 00 00 75 12 8b 29 25 ff 0f 00 00 03 c5 8b 2c 30 03 c6 03 ef 89 28 83 c2 02 4b 75 d3 8b 5c 24 14 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}