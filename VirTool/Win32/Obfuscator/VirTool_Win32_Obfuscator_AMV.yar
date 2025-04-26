
rule VirTool_Win32_Obfuscator_AMV{
	meta:
		description = "VirTool:Win32/Obfuscator.AMV,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 ec 08 dd 45 08 b8 ab aa aa aa dd 55 f8 f7 65 fc d9 ee dd 5d 08 d1 ea 81 c2 93 78 9f 2a } //1
		$a_01_1 = {8b 48 08 8b 50 04 89 4d e8 89 55 ec 8b 45 08 50 8d 4d cc 51 ff 55 0c 83 c4 08 8d 4d cc e8 9f 27 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}