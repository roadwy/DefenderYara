
rule VirTool_Win32_Obfuscator_WN{
	meta:
		description = "VirTool:Win32/Obfuscator.WN,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {05 01 01 01 00 05 01 01 01 01 89 45 ?? 8b 5d ?? ac 90 90 32 c3 90 90 aa f7 c1 01 00 00 00 74 0b 85 c0 60 6a 01 e8 ?? ?? ?? ?? 61 e2 } //1
		$a_03_1 = {b9 00 24 00 00 8b 35 ?? ?? ?? ?? 81 c6 ca 01 00 00 8b fe 51 b9 d2 de 0e 00 8b 45 ?? d1 c0 89 45 ?? e2 f6 59 eb } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}