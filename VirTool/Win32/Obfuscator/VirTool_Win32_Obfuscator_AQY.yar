
rule VirTool_Win32_Obfuscator_AQY{
	meta:
		description = "VirTool:Win32/Obfuscator.AQY,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {33 ca 89 8d ?? ?? ff ff 90 09 1a 00 0f be 8d ?? ?? ?? ?? 33 8d ?? ?? ?? ?? 0f be 95 } //1
		$a_01_1 = {ff d0 33 c0 5f 5e 5b 8b 4d f8 } //1
		$a_01_2 = {df e0 f6 c4 41 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}