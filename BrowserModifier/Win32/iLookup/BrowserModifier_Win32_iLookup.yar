
rule BrowserModifier_Win32_iLookup{
	meta:
		description = "BrowserModifier:Win32/iLookup,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 00 65 00 61 00 72 00 63 00 68 00 20 00 74 00 68 00 65 00 20 00 77 00 65 00 62 00 } //01 00 
		$a_01_1 = {3b 20 64 69 61 6c 6f 67 68 69 64 65 3a 20 30 3b 20 65 64 67 65 3a 20 73 75 6e 6b 65 6e 3b 20 68 65 6c 70 3a 20 30 3b 20 72 65 73 69 7a 61 62 6c 65 3a 20 30 3b 20 73 63 72 6f 6c 6c 3a 20 31 3b 20 73 74 61 74 75 73 3a 20 30 3b 20 75 6e 61 64 6f 72 6e 65 64 3a 20 30 3b } //01 00 
		$a_01_2 = {69 6e 65 62 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //00 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_iLookup_2{
	meta:
		description = "BrowserModifier:Win32/iLookup,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 63 6f 6d 2f 74 6f 6f 6c 62 61 72 2f 62 61 72 2f } //01 00 
		$a_01_1 = {69 6e 65 62 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //01 00 
		$a_01_2 = {42 72 6f 61 64 63 61 73 74 53 79 73 74 65 6d 4d 65 73 73 61 67 65 } //01 00 
		$a_01_3 = {70 6f 70 75 70 5f 65 6e 61 62 6c 65 64 } //01 00 
		$a_01_4 = {25 73 25 73 26 76 69 64 3d 25 6c 75 26 63 63 6f 64 3d 25 6c 75 } //00 00 
	condition:
		any of ($a_*)
 
}