
rule Backdoor_Win32_Regiskazi_A{
	meta:
		description = "Backdoor:Win32/Regiskazi.A,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 04 00 "
		
	strings :
		$a_01_0 = {26 6b 61 72 74 3d 4b 6f 74 75 4b 61 72 74 26 63 6f 72 65 3d 32 26 6d 68 7a 3d 59 41 56 41 53 } //04 00 
		$a_01_1 = {52 65 66 65 72 65 72 3a 20 57 69 6e 64 6f 77 73 58 50 2d 33 32 2d 4e 6f 6e 74 69 2d 4b 6f 74 75 4b 61 72 74 2d 32 2d 59 41 56 41 53 } //02 00 
		$a_01_2 = {66 64 73 66 64 73 66 64 73 66 5c 66 73 64 66 64 73 66 } //02 00 
		$a_01_3 = {21 63 61 6c 69 73 74 69 72 } //00 00 
		$a_00_4 = {5d 04 00 00 } //01 33 
	condition:
		any of ($a_*)
 
}