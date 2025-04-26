
rule VirTool_Win32_Obfuscator_BZA{
	meta:
		description = "VirTool:Win32/Obfuscator.BZA,SIGNATURE_TYPE_PEHSTR_EXT,32 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 8b 4d 0c 2b c8 8a 14 01 8a 18 32 da 88 18 40 4e 75 } //1
		$a_01_1 = {40 48 60 83 e8 0a 83 c0 0a 61 } //1
		$a_03_2 = {33 c0 c6 45 ?? 46 c6 45 ?? 75 c6 45 ?? 63 c6 45 ?? 6b } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}