
rule VirTool_Win32_Obfuscator_AQO{
	meta:
		description = "VirTool:Win32/Obfuscator.AQO,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 10 8b 94 24 28 02 00 00 8a 04 11 8b f5 8d 5d 03 0f af f7 0f af df 03 de 32 c3 85 ff 74 05 88 04 11 eb 03 88 14 11 } //1
		$a_01_1 = {8b c3 99 2b c2 d1 f8 8b ce 2b cf 0f af c8 8b 44 24 10 8d 55 04 0f af ca 03 ce 0f af cb 03 cf 40 03 e9 3b 84 24 2c 02 00 00 89 44 24 10 7c 92 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}