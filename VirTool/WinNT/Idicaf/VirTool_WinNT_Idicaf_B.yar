
rule VirTool_WinNT_Idicaf_B{
	meta:
		description = "VirTool:WinNT/Idicaf.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {8d 45 fc 50 6a 0b ff 15 90 01 02 01 00 60 b8 01 00 00 00 61 90 01 12 89 45 fc 0f 84 e1 00 00 00 90 00 } //02 00 
		$a_01_1 = {74 0e 8b 45 e0 c7 00 10 00 00 c0 e9 db 02 00 00 } //01 00 
		$a_01_2 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 58 00 50 00 53 00 41 00 46 00 45 00 00 00 } //01 00 
		$a_01_3 = {43 72 61 63 6b 4d 65 2e 73 79 73 00 } //00 00 
	condition:
		any of ($a_*)
 
}