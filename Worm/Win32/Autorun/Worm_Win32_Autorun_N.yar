
rule Worm_Win32_Autorun_N{
	meta:
		description = "Worm:Win32/Autorun.N,SIGNATURE_TYPE_PEHSTR,1e 00 1e 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {78 63 6f 70 79 20 74 68 47 2e 65 78 65 20 25 53 59 53 54 45 4d 52 4f 4f 54 25 } //0a 00 
		$a_01_1 = {65 63 68 6f 20 73 68 65 6c 6c 65 78 65 63 75 74 65 3d 74 68 47 2e 65 78 65 20 3e 3e 20 61 75 74 6f 72 75 6e 2e 69 6e 66 } //0a 00 
		$a_01_2 = {77 67 65 74 20 22 68 74 74 70 3a 2f 2f 76 69 72 61 65 2e 6f 72 67 2f 74 72 6f 6a 61 6e 68 6f 72 73 65 67 61 6c 6c 65 72 79 2f 67 65 74 2e 70 68 70 } //00 00 
	condition:
		any of ($a_*)
 
}