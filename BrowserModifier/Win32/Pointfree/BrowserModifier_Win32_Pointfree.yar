
rule BrowserModifier_Win32_Pointfree{
	meta:
		description = "BrowserModifier:Win32/Pointfree,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {2e 70 6f 69 6e 74 66 72 65 65 2e 63 6f 2e 6b 72 } //01 00 
		$a_00_1 = {72 65 67 73 76 72 33 32 20 2f 75 20 2f 73 20 } //01 00 
		$a_02_2 = {5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 90 02 1a 50 6f 69 6e 74 6d 61 6e 69 90 00 } //01 00 
		$a_00_3 = {2e 70 68 70 3f 49 4c 5f 4e 4f 3d } //01 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Pointfree_2{
	meta:
		description = "BrowserModifier:Win32/Pointfree,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {77 77 77 2e 70 6f 69 6e 74 66 72 65 65 2e 63 6f 2e 6b 72 2f 61 70 70 2f 72 65 6d 6f 76 65 2e 70 68 70 } //01 00 
		$a_01_1 = {5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 } //01 00 
		$a_01_2 = {26 6d 32 63 6f 64 65 3d 25 73 } //01 00 
		$a_01_3 = {52 65 63 6f 76 65 72 79 45 78 65 4e 61 6d 65 } //01 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Pointfree_3{
	meta:
		description = "BrowserModifier:Win32/Pointfree,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 02 00 "
		
	strings :
		$a_02_0 = {68 74 74 70 3a 2f 2f 90 02 04 2e 70 6f 69 6e 74 66 72 65 65 2e 63 6f 2e 6b 72 2f 90 00 } //02 00 
		$a_00_1 = {00 00 50 46 55 70 64 61 74 65 2e 65 78 65 00 00 } //02 00 
		$a_00_2 = {50 6f 69 6e 74 66 72 65 65 5c 50 46 48 65 6c 70 65 72 2e 62 61 6b } //01 00 
		$a_00_3 = {57 65 62 73 61 6c 65 53 79 73 74 65 6d 5c 57 65 62 73 48 50 2e 62 61 6b 00 } //01 00 
		$a_00_4 = {53 68 6f 70 43 65 6e 74 65 72 5c 53 68 6f 70 43 65 6e 74 65 72 48 65 6c 70 65 72 2e 62 61 6b 00 } //01 00 
		$a_00_5 = {52 65 73 74 61 72 74 2a 2e 62 61 74 22 } //01 00 
		$a_00_6 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 } //01 00 
	condition:
		any of ($a_*)
 
}