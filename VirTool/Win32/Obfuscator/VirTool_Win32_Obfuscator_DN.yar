
rule VirTool_Win32_Obfuscator_DN{
	meta:
		description = "VirTool:Win32/Obfuscator.DN,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {58 ff d0 40 e8 00 00 00 00 2d 90 01 04 01 04 24 ff 14 24 2d 90 01 04 83 7d f4 00 75 05 90 00 } //3
		$a_03_1 = {58 ff d0 40 e8 00 00 00 00 2d 90 01 04 01 04 24 8b 04 24 ff d0 2d 90 01 04 83 7d f4 00 75 05 90 00 } //3
		$a_01_2 = {0f b7 45 f0 85 c0 74 08 6a 00 } //1
		$a_01_3 = {0f 00 45 f0 } //1
		$a_01_4 = {e8 00 00 00 00 58 25 00 f0 ff ff 05 00 12 00 00 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*2) >=5
 
}