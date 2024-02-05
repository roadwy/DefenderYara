
rule Backdoor_WinNT_Jrat_C{
	meta:
		description = "Backdoor:WinNT/Jrat.C,SIGNATURE_TYPE_JAVAHSTR_EXT,06 00 06 00 04 00 00 04 00 "
		
	strings :
		$a_01_0 = {0c 0e 4f 0f 45 09 58 1f 4f 52 4e 1d 5e } //04 00 
		$a_01_1 = {0e 0f 5e 09 48 1f 45 12 4c 15 4d 52 5e 04 5e } //01 00 
		$a_01_2 = {0d 41 4c 4c 41 54 4f 52 49 78 44 45 4d 4f } //01 00 
		$a_01_3 = {2f 62 72 69 64 6a 2f 6a 61 77 74 2f } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_WinNT_Jrat_C_2{
	meta:
		description = "Backdoor:WinNT/Jrat.C,SIGNATURE_TYPE_JAVAHSTR_EXT,09 00 09 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {05 37 37 24 4e 5a } //01 00 
		$a_01_1 = {0d 11 07 10 0d 16 10 c0 80 07 4d 06 02 16 } //01 00 
		$a_01_2 = {0a 64 65 63 6f 6d 70 72 65 73 73 } //01 00 
		$a_01_3 = {11 63 6f 6e 66 69 67 2f 42 79 74 65 4c 6f 61 64 65 72 } //05 00 
		$a_01_4 = {84 03 ff 1c 82 92 55 1d 9b 00 16 2b 2a 1d 84 03 ff } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_WinNT_Jrat_C_3{
	meta:
		description = "Backdoor:WinNT/Jrat.C,SIGNATURE_TYPE_JAVAHSTR_EXT,0b 00 0b 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {0c 50 49 4e 47 52 45 53 50 4f 4e 53 45 } //01 00 
		$a_01_1 = {08 53 54 41 52 54 43 41 4d } //01 00 
		$a_01_2 = {0a 4f 46 46 4c 49 4e 45 4c 4f 47 } //01 00 
		$a_01_3 = {08 45 58 50 4c 4f 52 45 52 } //01 00 
		$a_01_4 = {09 49 4e 4a 45 43 54 4a 41 52 } //01 00 
		$a_01_5 = {0d 4c 4f 41 44 50 52 4f 43 45 53 53 45 53 } //05 00 
		$a_01_6 = {0b 48 65 61 64 65 72 2e 6a 61 76 61 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_WinNT_Jrat_C_4{
	meta:
		description = "Backdoor:WinNT/Jrat.C,SIGNATURE_TYPE_JAVAHSTR_EXT,0a 00 0a 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {14 4c 66 75 7a 7a 6c 65 2f 42 43 4a 49 6e 6a 65 63 74 6f 72 3b } //04 00 
		$a_01_1 = {11 4c 63 6f 6e 66 69 67 2f 52 65 67 69 73 74 72 79 3b } //01 00 
		$a_01_2 = {13 4c 63 6f 6e 66 69 67 2f 42 79 74 65 4c 6f 61 64 65 72 3b } //04 00 
		$a_01_3 = {0d 63 6f 6e 66 69 67 2f 52 65 61 64 49 4f } //01 00 
		$a_01_4 = {07 5d 15 44 18 45 0b 59 } //01 00 
		$a_01_5 = {06 14 43 18 4e 19 44 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_WinNT_Jrat_C_5{
	meta:
		description = "Backdoor:WinNT/Jrat.C,SIGNATURE_TYPE_JAVAHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 6a 73 74 65 61 6c 74 68 2f 61 70 69 2f 6c 6f 61 64 65 72 73 2f 43 43 4c 6f 61 64 65 72 } //01 00 
		$a_01_1 = {2f 6a 73 74 65 61 6c 74 68 2f 61 70 69 2f 43 6c 69 65 6e 74 50 6c 75 67 69 6e } //01 00 
		$a_01_2 = {14 4a 61 72 49 6e 6a 65 63 74 55 70 6c 6f 61 64 2e 6a 61 76 61 } //01 00 
		$a_01_3 = {6e 65 74 2f 6f 73 63 70 2f 63 6c 69 65 6e 74 2f 6a 61 72 69 6e 6a 65 63 74 6f 72 2f 4a 61 72 49 6e 6a 65 63 74 55 70 6c 6f 61 64 } //01 00 
		$a_01_4 = {0e 63 72 65 61 74 65 54 65 6d 70 46 69 6c 65 } //01 00 
		$a_01_5 = {04 2e 6a 61 72 } //00 00 
	condition:
		any of ($a_*)
 
}