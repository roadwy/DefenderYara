
rule PWS_Win32_Lesword_B{
	meta:
		description = "PWS:Win32/Lesword.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {25 64 26 6c 3d 25 73 26 73 6c 3d 25 73 26 6d 61 63 3d 25 73 26 6d 62 68 3d 25 64 90 02 01 4e 55 4c 4c 90 02 10 7a 68 65 6e 67 74 75 32 2e 64 61 74 90 02 20 5c 64 6f 77 6e 6c 6f 61 64 90 02 02 2e 64 6c 6c 90 00 } //01 00 
		$a_02_1 = {4d 55 49 43 61 63 68 65 00 63 6d 64 20 2f 63 20 25 73 90 02 05 61 2e 72 65 67 90 02 05 57 69 6e 64 6f 77 73 20 52 65 67 90 00 } //01 00 
		$a_02_2 = {50 4f 53 54 90 02 05 2e 6a 70 67 90 02 10 41 43 44 90 02 10 25 73 3f 64 31 30 3d 25 73 26 64 38 30 3d 25 64 90 02 0a 25 73 5c 25 73 2e 73 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}