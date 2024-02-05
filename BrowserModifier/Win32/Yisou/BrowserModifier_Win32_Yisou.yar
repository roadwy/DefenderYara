
rule BrowserModifier_Win32_Yisou{
	meta:
		description = "BrowserModifier:Win32/Yisou,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {7b 45 46 31 44 31 37 41 39 2d 30 38 39 46 2d 34 30 63 63 2d 38 44 36 34 2d 37 33 32 34 43 44 45 42 41 30 44 42 7d 00 00 59 69 53 6f 75 00 00 00 44 72 61 67 53 65 61 72 63 68 } //01 00 
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 33 37 32 31 5c 79 69 73 6f 75 } //01 00 
		$a_01_2 = {63 6c 69 65 6e 74 5f 62 61 72 5f 73 64 72 61 67 26 70 3d 25 73 } //01 00 
		$a_01_3 = {42 68 6f 4f 62 6a 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //00 00 
	condition:
		any of ($a_*)
 
}