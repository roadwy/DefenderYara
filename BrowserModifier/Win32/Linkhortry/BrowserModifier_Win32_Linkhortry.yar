
rule BrowserModifier_Win32_Linkhortry{
	meta:
		description = "BrowserModifier:Win32/Linkhortry,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {2f 63 20 22 73 74 61 72 74 20 25 73 22 } //02 00 
		$a_01_1 = {72 65 66 67 64 66 62 66 67 68 6a 75 79 75 6a 6b } //01 00 
		$a_01_2 = {64 68 65 65 63 64 6c 64 6f 6b 67 64 73 73 00 00 78 6c 6c 6c 72 69 66 6b 67 67 73 64 6f 65 00 00 } //01 00 
		$a_01_3 = {2d 73 74 61 70 70 20 2d 73 74 61 70 70 } //00 00 
	condition:
		any of ($a_*)
 
}