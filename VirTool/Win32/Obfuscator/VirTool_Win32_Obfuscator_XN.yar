
rule VirTool_Win32_Obfuscator_XN{
	meta:
		description = "VirTool:Win32/Obfuscator.XN,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {ac 84 c0 74 09 0c 21 32 d0 c1 c2 0b eb f2 } //1
		$a_01_1 = {fd ab 2d 04 04 04 04 e2 f8 fc } //1
		$a_01_2 = {68 64 6c 6c 00 68 64 6c 6c 2e 68 73 62 69 65 8b c4 50 } //1
		$a_03_3 = {b0 68 aa 8b 45 08 2b 45 ?? 03 45 ?? ab b0 c3 aa } //1
		$a_01_4 = {0f 31 50 0f 31 5a 2b c2 3d 00 02 00 00 73 12 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}