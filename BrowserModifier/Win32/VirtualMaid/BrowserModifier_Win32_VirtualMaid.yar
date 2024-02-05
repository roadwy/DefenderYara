
rule BrowserModifier_Win32_VirtualMaid{
	meta:
		description = "BrowserModifier:Win32/VirtualMaid,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 04 00 "
		
	strings :
		$a_01_0 = {56 69 72 74 75 61 6c 20 4d 61 69 64 20 20 63 61 6e 27 74 20 72 65 74 72 69 76 65 20 69 6e 66 6f 6d 61 74 69 6f 6e 20 66 72 6f 6d } //03 00 
		$a_00_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 72 00 73 00 64 00 6e 00 2e 00 72 00 75 00 2f 00 63 00 67 00 69 00 2d 00 62 00 69 00 6e 00 2f 00 73 00 65 00 61 00 72 00 63 00 68 00 2e 00 65 00 78 00 65 00 3f 00 71 00 75 00 65 00 72 00 79 00 3d 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_VirtualMaid_2{
	meta:
		description = "BrowserModifier:Win32/VirtualMaid,SIGNATURE_TYPE_PEHSTR_EXT,10 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_00_0 = {56 69 72 74 75 61 6c 20 4d 61 69 64 } //05 00 
		$a_00_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 73 65 61 72 63 68 6d 61 69 64 2e 63 6f 6d 2f } //05 00 
		$a_01_2 = {4d 41 49 44 42 4d 50 32 00 } //01 00 
		$a_00_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 53 65 61 72 63 68 55 72 6c } //01 00 
		$a_00_4 = {43 6c 6f 73 65 41 6c 6c 52 75 6e 49 45 20 45 6e 64 20 6f 66 20 43 61 6c 6c } //01 00 
		$a_00_5 = {4d 41 49 44 44 4c 4c 00 56 69 72 74 75 61 6c 20 4d 61 69 64 } //00 00 
	condition:
		any of ($a_*)
 
}