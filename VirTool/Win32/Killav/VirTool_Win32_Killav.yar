
rule VirTool_Win32_Killav{
	meta:
		description = "VirTool:Win32/Killav,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {41 6e 74 69 4b 61 73 70 65 72 73 6b 79 20 } //01 00 
		$a_00_1 = {42 75 69 6c 64 3a 20 } //01 00 
		$a_00_2 = {6b 61 73 32 6b 2c 20 74 6f 6f 6c 7a 2e 70 79 63 63 78 61 6b 2e 63 6f 6d } //01 00 
		$a_00_3 = {45 72 72 6f 72 20 4e 31 21 2c 20 43 6f 6d 6d 61 6e 64 4c 69 6e 65 20 4e 55 4c 4c 2e } //01 00 
		$a_00_4 = {46 69 6c 65 20 43 72 79 70 74 65 64 21 } //01 00 
		$a_01_5 = {46 55 43 4b } //00 00 
	condition:
		any of ($a_*)
 
}