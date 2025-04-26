
rule VirTool_WinNT_Idicaf_C{
	meta:
		description = "VirTool:WinNT/Idicaf.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {81 7f 0c 00 f8 00 80 74 } //1
		$a_01_1 = {b9 d4 40 07 00 3b c1 } //1
		$a_03_2 = {85 c9 74 13 8b 50 40 3b ca 74 0c 89 15 ?? ?? ?? ?? 89 48 40 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}