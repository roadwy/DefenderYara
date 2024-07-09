
rule VirTool_Win32_Obfuscator_AGE{
	meta:
		description = "VirTool:Win32/Obfuscator.AGE,SIGNATURE_TYPE_PEHSTR_EXT,58 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 42 08 8b 72 0c 8b 91 b0 00 00 00 8b b9 9c 00 00 00 2b c2 1b fe 75 60 ?? 10 27 00 00 } //2
		$a_00_1 = {8b 45 a8 03 85 54 ff ff ff 89 85 50 ff ff ff 8b 4d 08 51 6a 01 8b 55 a8 52 ff 95 50 ff ff ff } //1
		$a_01_2 = {68 b4 8b 96 4f e8 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}