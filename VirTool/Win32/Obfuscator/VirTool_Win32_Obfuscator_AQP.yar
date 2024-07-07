
rule VirTool_Win32_Obfuscator_AQP{
	meta:
		description = "VirTool:Win32/Obfuscator.AQP,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b c7 0f af c7 99 8d 5e 02 f7 fb 8d 0c 37 8b d8 8b 45 f4 0f af c1 8b 4d 08 c1 e0 02 2b d8 8b 45 f8 8d 14 08 8a 02 32 c3 85 f6 74 04 88 02 eb 02 } //1
		$a_01_1 = {33 c9 41 2b cf 2b ce 8d 04 37 0f af c8 8b c3 0f af c7 03 c8 0f af cb 8b c6 c1 e0 02 03 c8 0f af 4d f4 03 f9 ff 45 f8 8b 45 f8 3b 45 0c 0f 8c 20 ff ff ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}