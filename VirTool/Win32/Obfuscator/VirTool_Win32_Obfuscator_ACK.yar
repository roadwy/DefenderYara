
rule VirTool_Win32_Obfuscator_ACK{
	meta:
		description = "VirTool:Win32/Obfuscator.ACK,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {3a 5c 44 65 62 75 67 67 65 72 2e 66 67 68 00 } //1
		$a_00_1 = {8b 4d 34 8b 01 8b 11 03 50 3c 8b 45 0c 89 10 8b 10 8b 01 8b 09 03 82 a0 00 00 00 8b 55 30 2b ca 8b 55 08 89 0a 8b 4d 0c 8b 11 8b 4d 34 8b 09 03 4a 28 } //1
		$a_00_2 = {0f b6 d2 0f b6 94 15 38 ff ff ff c1 e0 06 03 45 b8 41 c1 e0 06 03 c7 c1 e0 06 03 c2 3b 75 10 73 25 8b 7d 0c 8b d0 c1 ea 10 88 14 3e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=2
 
}