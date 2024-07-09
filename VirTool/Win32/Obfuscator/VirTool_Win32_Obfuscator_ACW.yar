
rule VirTool_Win32_Obfuscator_ACW{
	meta:
		description = "VirTool:Win32/Obfuscator.ACW,SIGNATURE_TYPE_PEHSTR_EXT,64 00 0b 00 05 00 00 "
		
	strings :
		$a_0b_0 = {68 22 07 e4 71 50 e8 ?? ?? 00 00 89 85 ?? ?? ff ff 58 68 b6 74 75 5d 50 e8 ?? ?? 00 00 89 85 ?? ?? ff ff b8 f4 1c 19 0f 50 57 e8 ?? ?? 00 00 92 6a 00 [0-02] ff d2 } //5
		$a_09_1 = {c7 42 08 40 90 90 90 c7 42 0c ff 74 e4 f0 c7 42 10 c3 90 90 90 } //1
		$a_09_2 = {c7 42 10 c3 90 90 90 c7 42 0c ff 74 e4 f0 c7 42 08 40 90 90 90 } //1
		$a_09_3 = {c7 42 10 c3 90 90 90 c7 42 04 e4 83 c4 10 c7 42 08 40 90 90 90 } //1
		$a_09_4 = {51 81 fa 6b 6f 72 65 59 } //5
	condition:
		((#a_0b_0  & 1)*5+(#a_09_1  & 1)*1+(#a_09_2  & 1)*1+(#a_09_3  & 1)*1+(#a_09_4  & 1)*5) >=11
 
}