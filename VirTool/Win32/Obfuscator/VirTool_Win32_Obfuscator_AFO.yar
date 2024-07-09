
rule VirTool_Win32_Obfuscator_AFO{
	meta:
		description = "VirTool:Win32/Obfuscator.AFO,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 34 07 8a c1 02 c0 32 06 32 45 ?? 3c ?? 75 17 33 d2 3b f9 0f 94 c2 33 55 ?? 74 0b 83 7d ?? 03 7d 05 8a 55 ?? 88 16 88 06 83 f9 04 7e 05 } //1
		$a_03_1 = {0f b6 14 07 d3 e2 31 c2 01 da 30 14 1e 40 39 45 ?? 77 ed 89 d8 ba 00 00 00 00 f7 75 ?? 8a 04 17 30 04 1e 43 39 5d ?? 76 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}