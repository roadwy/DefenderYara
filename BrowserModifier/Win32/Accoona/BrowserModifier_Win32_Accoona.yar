
rule BrowserModifier_Win32_Accoona{
	meta:
		description = "BrowserModifier:Win32/Accoona,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 53 65 61 72 63 68 41 73 73 69 73 74 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //01 00 
		$a_01_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 61 63 63 6f 6f 6e 61 2e 63 6f 6d 2f } //01 00 
		$a_01_2 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 41 63 63 6f 6f 6e 61 } //00 00 
	condition:
		any of ($a_*)
 
}