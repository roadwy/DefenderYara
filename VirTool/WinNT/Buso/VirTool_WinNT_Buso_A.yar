
rule VirTool_WinNT_Buso_A{
	meta:
		description = "VirTool:WinNT/Buso.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {74 0f 8b 4d 10 8a 11 80 f2 ?? 88 10 40 41 4e 75 f4 80 20 00 } //1
		$a_00_1 = {74 08 c7 02 10 00 00 c0 eb 57 56 8b 75 10 3b f7 74 48 39 7d 14 74 43 8b 4d 14 c1 e9 02 8b c1 c1 e0 02 3b 45 14 75 33 fa 0f 20 c0 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}