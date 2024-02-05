
rule PWS_Win32_Frethog_AI{
	meta:
		description = "PWS:Win32/Frethog.AI,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {26 69 6e 74 72 6f 3d 00 26 75 72 6c 3d 00 } //01 00 
		$a_01_1 = {00 4e 75 6d 00 45 6e 74 65 72 } //01 00 
		$a_01_2 = {25 73 0a 00 64 61 74 61 5c } //02 00 
		$a_01_3 = {3b c2 7e 79 81 c1 1e 02 00 00 3b c1 7d 6f 8d 45 fc 50 56 } //03 00 
		$a_01_4 = {6a 04 50 68 b4 5e f7 01 57 ff d6 } //03 00 
		$a_01_5 = {6a 04 50 68 94 56 f7 01 57 ff d6 8d 45 10 50 6a 14 68 } //00 00 
	condition:
		any of ($a_*)
 
}