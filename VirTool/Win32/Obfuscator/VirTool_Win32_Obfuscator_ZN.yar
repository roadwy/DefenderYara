
rule VirTool_Win32_Obfuscator_ZN{
	meta:
		description = "VirTool:Win32/Obfuscator.ZN,SIGNATURE_TYPE_PEHSTR_EXT,04 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 00 8b 00 8b 40 18 [0-20] 89 45 ?? c6 45 ?? 50 c6 45 ?? 41 c6 45 ?? 47 } //1
		$a_01_1 = {8d 50 01 8b 4d f4 03 51 08 8d 14 92 33 c9 8a 0c 07 33 d1 4a 88 14 07 40 4b 75 e5 } //1
		$a_01_2 = {8d 50 01 8b 75 ec 0f af 56 04 8b 75 f4 0f b6 34 06 33 d6 8b 75 f4 88 14 06 43 40 49 75 da } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}