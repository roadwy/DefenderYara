
rule Worm_Win32_Autorun_LB{
	meta:
		description = "Worm:Win32/Autorun.LB,SIGNATURE_TYPE_PEHSTR,28 00 23 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 65 78 70 6c 6f 72 65 72 5c 58 71 64 42 68 6f } //0a 00 
		$a_01_1 = {41 75 74 6f 72 75 6e 2e 69 6e 66 } //0a 00 
		$a_01_2 = {73 68 65 6c 6c 5c 41 75 74 6f 5c 63 6f 6d 6d 61 6e 64 } //05 00 
		$a_01_3 = {53 45 52 56 49 43 53 2e 45 58 45 } //05 00 
		$a_01_4 = {53 43 56 48 30 53 54 2e 45 58 45 } //00 00 
	condition:
		any of ($a_*)
 
}