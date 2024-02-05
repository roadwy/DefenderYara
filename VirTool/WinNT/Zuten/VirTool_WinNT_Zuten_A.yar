
rule VirTool_WinNT_Zuten_A{
	meta:
		description = "VirTool:WinNT/Zuten.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 02 00 "
		
	strings :
		$a_02_0 = {8b 75 10 6a 05 56 e8 90 01 02 ff ff 2b de 83 c3 0b c6 06 e9 89 5e 01 8b 4d 2c ff 15 90 00 } //03 00 
		$a_00_1 = {5c 44 6f 73 44 65 76 69 63 65 73 5c 63 3a 5c 6e 61 6d 65 2e 6c 6f 67 00 } //03 00 
		$a_00_2 = {84 21 10 80 75 } //02 00 
		$a_00_3 = {47 61 6d 65 48 61 63 6b 5c } //01 00 
		$a_00_4 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}