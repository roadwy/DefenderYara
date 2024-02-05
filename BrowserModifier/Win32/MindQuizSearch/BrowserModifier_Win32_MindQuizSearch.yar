
rule BrowserModifier_Win32_MindQuizSearch{
	meta:
		description = "BrowserModifier:Win32/MindQuizSearch,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 4d 69 6e 64 51 75 69 7a 53 65 61 72 63 68 54 6f 6f 6c 62 61 72 00 70 72 65 66 28 22 65 78 74 65 6e 73 69 6f 6e 73 2e 73 65 61 72 63 68 74 6f 6f 6c 62 61 72 } //01 00 
		$a_01_1 = {74 72 61 63 6b 2e 7a 75 67 6f 2e 63 6f 6d 2f 63 67 69 2d 62 69 6e 2f 64 65 62 75 67 2e 70 79 3f 66 69 6c 65 6e 61 6d 65 3d 6d 69 6e 64 71 75 69 7a 73 65 74 75 70 2d 73 69 6c 65 6e 74 2d 69 5f 61 63 63 65 70 74 26 75 72 6c 3d } //00 00 
	condition:
		any of ($a_*)
 
}