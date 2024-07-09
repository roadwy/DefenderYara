
rule VirTool_Win32_Obfuscator_ACN{
	meta:
		description = "VirTool:Win32/Obfuscator.ACN,SIGNATURE_TYPE_PEHSTR_EXT,05 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4d 08 8b 55 ?? 83 c0 04 8b 30 89 34 8a 8b 4d ?? 8b 55 08 33 cf 8d 8c 11 ?? ?? ?? ?? 89 4d 08 8b 4d 08 8b 55 14 3b ca 0f 85 d2 ff ff ff } //1
		$a_03_1 = {33 f0 33 f8 03 fa 8d 94 37 ?? ?? ?? ?? 8b 75 ec 33 f0 03 f1 3b d6 0f 82 a0 ff ff ff 8b 45 f8 a3 ?? ?? ?? ?? 8b 45 f0 8b 0d ?? ?? ?? ?? 03 c1 21 45 fc a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 01 08 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}