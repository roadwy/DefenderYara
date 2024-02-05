
rule HackTool_Win32_Gamehack_G_MSR{
	meta:
		description = "HackTool:Win32/Gamehack.G!MSR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 6f 75 6c 64 6e 27 74 20 66 69 6e 64 20 63 73 67 6f 2e 65 78 65 21 } //01 00 
		$a_01_1 = {6a 75 73 74 47 6c 6f 77 2e 70 64 62 } //01 00 
		$a_01_2 = {47 4c 4f 57 48 41 43 4b 3a } //00 00 
		$a_00_3 = {78 } //e2 00 
	condition:
		any of ($a_*)
 
}
rule HackTool_Win32_Gamehack_G_MSR_2{
	meta:
		description = "HackTool:Win32/Gamehack.G!MSR,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {45 78 70 6c 6f 69 74 73 5c 45 78 70 6c 6f 69 74 2d 41 50 49 5c 52 65 6c 65 61 73 65 5c 65 78 70 6c 6f 69 74 2d 6d 61 69 6e 2e 70 64 62 } //01 00 
		$a_01_1 = {52 6f 62 6c 6f 78 2f 65 78 70 6c 6f 69 74 20 63 72 61 73 68 65 64 2e } //01 00 
		$a_01_2 = {4b 65 65 70 20 63 72 61 73 68 69 6e 67 3f 20 4d 61 6b 65 20 73 75 72 65 20 52 6f 62 6c 6f 78 20 69 73 20 63 6c 6f 73 65 64 20 69 6e 20 74 68 65 20 74 61 73 6b 20 6d 61 6e 61 67 65 72 } //01 00 
		$a_01_3 = {50 6c 65 61 73 65 20 72 65 6a 6f 69 6e 20 74 68 65 20 67 61 6d 65 20 61 6e 64 20 72 65 74 72 79 } //01 00 
		$a_01_4 = {73 63 72 69 70 74 3d 49 6e 73 74 61 6e 63 65 2e 6e 65 77 28 22 4c 6f 63 61 6c 53 63 72 69 70 74 22 29 } //00 00 
		$a_00_5 = {7e 15 00 00 b2 } //85 33 
	condition:
		any of ($a_*)
 
}