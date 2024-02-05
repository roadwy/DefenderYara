
rule BrowserModifier_Win32_Suchspur{
	meta:
		description = "BrowserModifier:Win32/Suchspur,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0a 00 05 00 00 03 00 "
		
	strings :
		$a_01_0 = {53 75 63 68 73 70 75 72 2e 64 6c 6c } //03 00 
		$a_01_1 = {57 65 62 50 72 65 66 69 78 } //03 00 
		$a_01_2 = {21 41 44 57 41 52 45 5f 53 46 58 21 } //01 00 
		$a_01_3 = {25 30 38 58 2d 25 30 34 58 2d 25 30 34 58 2d 25 30 32 58 25 30 32 58 2d 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 } //01 00 
		$a_01_4 = {31 68 70 3d 73 74 65 75 64 66 2f 61 72 } //00 00 
	condition:
		any of ($a_*)
 
}