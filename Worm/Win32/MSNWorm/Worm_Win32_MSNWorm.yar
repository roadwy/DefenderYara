
rule Worm_Win32_MSNWorm{
	meta:
		description = "Worm:Win32/MSNWorm,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 08 00 00 03 00 "
		
	strings :
		$a_01_0 = {50 52 49 56 4d 53 47 20 25 73 20 3a 20 77 6f 77 3a 20 25 73 } //01 00 
		$a_01_1 = {68 02 20 00 00 ff 15 } //02 00 
		$a_01_2 = {6a 00 6a 01 6a 00 6a 11 ff } //01 00 
		$a_01_3 = {6a 00 6a 00 6a 00 6a 0d ff } //01 00 
		$a_01_4 = {2e 7a 69 70 00 } //02 00 
		$a_01_5 = {41 2d 9e 24 dd 44 64 4d 9b 6b d5 fd 76 } //02 00 
		$a_01_6 = {6a 00 6a 03 6a 2d 6a 11 ff } //01 00 
		$a_01_7 = {53 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //01 00 
	condition:
		any of ($a_*)
 
}