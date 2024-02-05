
rule VirTool_WinNT_Idicaf_C{
	meta:
		description = "VirTool:WinNT/Idicaf.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {81 7f 0c 00 f8 00 80 74 } //01 00 
		$a_01_1 = {b9 d4 40 07 00 3b c1 } //01 00 
		$a_03_2 = {85 c9 74 13 8b 50 40 3b ca 74 0c 89 15 90 01 04 89 48 40 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}