
rule VirTool_Win32_Obfuscator_CW{
	meta:
		description = "VirTool:Win32/Obfuscator.CW,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {83 e6 03 75 11 8b 5d 10 66 01 da 6b d2 ?? c1 ca ?? f7 d2 89 55 10 30 10 40 c1 ca ?? e2 e0 c9 } //1
		$a_03_1 = {83 e6 03 75 0f 8b 5d 10 66 01 da 6b d2 ?? c1 c2 ?? 89 55 10 30 10 40 c1 ca ?? e2 e2 c9 } //1
		$a_03_2 = {83 e6 03 75 12 8b 5d 10 66 01 da 6b d2 ?? 66 f7 (d2|da) c1 90 03 01 01 c2 ca ?? 89 55 10 30 10 40 c1 ca ?? e2 df c9 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}