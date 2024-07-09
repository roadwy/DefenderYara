
rule VirTool_Win32_Obfuscator_ABD{
	meta:
		description = "VirTool:Win32/Obfuscator.ABD,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {59 8b d8 43 6a 40 68 00 10 00 00 53 57 ff 15 ?? ?? ?? ?? 8d 4d f4 89 45 fc 51 50 8b fe 83 c9 ff 33 c0 f2 ae f7 d1 } //1
		$a_03_1 = {6a 25 33 c0 59 8d bd ?? ?? ff ff f3 ab 8d 85 ?? ?? ff ff c7 85 ?? ?? ff ff 94 00 00 00 50 ff 15 } //1
		$a_01_2 = {8a d9 c0 fb 04 80 e3 03 c0 e0 02 0a d8 8b 45 10 88 1c 07 47 8a 04 16 46 3c 3d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}