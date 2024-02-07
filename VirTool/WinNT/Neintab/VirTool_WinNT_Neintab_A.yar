
rule VirTool_WinNT_Neintab_A{
	meta:
		description = "VirTool:WinNT/Neintab.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 02 00 05 00 00 04 00 "
		
	strings :
		$a_02_0 = {8b 51 70 89 15 90 01 02 01 00 8b 45 08 8b 48 40 89 0d 90 01 02 01 00 8d 55 fc 52 68 90 01 02 01 00 8b 45 08 8b 48 0c 51 e8 90 01 02 00 00 89 45 d4 68 90 00 } //04 00 
		$a_02_1 = {83 7d e4 00 75 05 e9 12 01 00 00 8d 45 f4 50 8b 4d ec 51 8b 55 e4 52 6a 0b e8 90 01 02 00 00 89 45 f0 81 7d f0 04 00 00 c0 75 54 90 00 } //01 00 
		$a_01_2 = {69 6e 69 74 20 6e 6b 6c 69 62 20 76 65 72 73 69 6f 6e 20 25 73 20 20 62 75 69 6c 74 20 25 73 } //01 00  init nklib version %s  built %s
		$a_03_3 = {64 3a 5c 70 72 6f 6a 5c 6e 6b 90 02 07 5c 73 72 63 5c 6e 6b 6c 69 62 5c 90 00 } //01 00 
		$a_03_4 = {64 3a 5c 70 72 6f 6a 5c 6e 6b 90 02 07 5c 6f 75 74 5c 69 33 38 36 5c 6e 6b 76 32 2e 70 64 62 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}