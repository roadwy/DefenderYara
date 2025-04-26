
rule VirTool_Win32_Obfuscator_YP{
	meta:
		description = "VirTool:Win32/Obfuscator.YP,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 06 03 c7 8b f1 99 f7 fe 8b 84 95 f4 fb ff ff 30 03 8b 45 10 05 3c c9 00 00 ff 45 fc 89 45 10 8b 45 fc 3b 45 0c 7c 93 5f } //1
		$a_03_1 = {40 00 43 43 58 31 0f 85 9a 01 00 00 83 3d ?? ?? 40 00 01 0f 85 8d 01 00 00 bf 82 09 00 00 be 48 c7 40 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}