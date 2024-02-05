
rule BrowserModifier_Win32_HMToolbar{
	meta:
		description = "BrowserModifier:Win32/HMToolbar,SIGNATURE_TYPE_PEHSTR,20 00 14 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {54 4f 4f 4c 42 41 52 20 6e 61 6d 65 3d 22 68 6d 74 6f 6f 6c 62 61 72 22 } //0a 00 
		$a_01_1 = {55 4e 50 4f 50 55 50 00 50 4f 50 55 50 } //0a 00 
		$a_01_2 = {68 74 74 70 3a 2f 2f 74 6f 6f 6c 2e 77 6f 72 6c 64 32 2e 63 6e 2f 74 6f 6f 6c 62 61 72 2f } //01 00 
		$a_01_3 = {6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 6f 6e 63 65 } //01 00 
		$a_01_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 54 6f 6f 6c 62 61 72 } //00 00 
	condition:
		any of ($a_*)
 
}