
rule Backdoor_Win32_Begman_B{
	meta:
		description = "Backdoor:Win32/Begman.B,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 04 00 00 03 00 "
		
	strings :
		$a_01_0 = {77 75 73 61 20 2f 71 75 69 65 74 20 } //02 00 
		$a_01_1 = {2c 4d 61 69 6e 42 65 67 69 6e } //02 00 
		$a_01_2 = {73 68 65 6c 6c 5c 45 78 70 6c 6f 72 65 5c 63 6f 6d 6d 61 6e 64 3d } //02 00 
		$a_01_3 = {65 78 70 61 6e 64 20 2d 72 20 } //00 00 
	condition:
		any of ($a_*)
 
}