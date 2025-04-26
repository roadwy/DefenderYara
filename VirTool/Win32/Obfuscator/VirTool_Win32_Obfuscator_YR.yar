
rule VirTool_Win32_Obfuscator_YR{
	meta:
		description = "VirTool:Win32/Obfuscator.YR,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {bb 0a 00 00 00 6a 00 6a 00 ff d6 ff d7 4b 75 f5 bb 0a 00 00 00 6a 00 6a 00 ff d6 ff d7 4b 75 f5 8b 44 24 10 } //1
		$a_03_1 = {88 14 08 f6 c1 01 74 14 a1 e0 ?? (42|43) 00 8a 14 08 32 15 c0 ?? (42|43) 00 80 f2 74 88 14 08 41 81 f9 00 d0 07 00 7c a2 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}