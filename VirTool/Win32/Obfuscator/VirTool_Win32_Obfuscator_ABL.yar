
rule VirTool_Win32_Obfuscator_ABL{
	meta:
		description = "VirTool:Win32/Obfuscator.ABL,SIGNATURE_TYPE_PEHSTR_EXT,64 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3b c6 75 04 33 c0 eb 37 50 56 ff 15 } //1
		$a_03_1 = {8b 44 24 0c 8d ?? ?? 33 d2 6a ?? 8b ?? 5f f7 f7 8a 82 ?? ?? ?? ?? 30 ?? ?? 3b ?? 24 10 76 e1 5f } //1
		$a_01_2 = {66 3b 48 06 73 4d 8b 0d } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}