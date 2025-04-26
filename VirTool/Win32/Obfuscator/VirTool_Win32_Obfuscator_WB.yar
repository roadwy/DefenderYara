
rule VirTool_Win32_Obfuscator_WB{
	meta:
		description = "VirTool:Win32/Obfuscator.WB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 8d d8 fb ff ff 8a 04 08 32 84 95 e0 fb ff ff 8b 4d 18 8b 11 8b 8d d8 fb ff ff 88 04 0a } //1
		$a_01_1 = {8b 95 a8 fe ff ff 52 8b 85 38 fe ff ff 50 ff 95 98 fb ff ff } //1
		$a_01_2 = {0f 85 1c 02 00 00 8b 55 b4 3b 55 e4 0f 85 a6 00 00 00 8b 45 c4 2b 45 e4 83 c0 01 e9 07 02 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}