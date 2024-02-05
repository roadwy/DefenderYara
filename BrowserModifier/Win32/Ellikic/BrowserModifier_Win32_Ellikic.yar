
rule BrowserModifier_Win32_Ellikic{
	meta:
		description = "BrowserModifier:Win32/Ellikic,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 04 00 "
		
	strings :
		$a_01_0 = {77 77 77 2e 69 6c 69 6b 65 63 6c 69 63 6b 2e 63 6f 6d 2f 74 72 61 63 6b } //03 00 
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 64 6c 6c 5f 31 5f 6c 61 73 74 74 69 6d 65 } //02 00 
		$a_01_2 = {3c 69 66 72 61 6d 65 20 73 72 63 3d 22 25 73 22 20 77 69 64 74 68 3d 30 20 68 65 69 67 68 74 3d 30 3e 3c 2f 69 66 72 61 6d 65 3e } //00 00 
	condition:
		any of ($a_*)
 
}