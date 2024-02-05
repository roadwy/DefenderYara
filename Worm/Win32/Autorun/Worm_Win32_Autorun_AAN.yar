
rule Worm_Win32_Autorun_AAN{
	meta:
		description = "Worm:Win32/Autorun.AAN,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 61 73 6b 6b 69 6c 6c 20 2d 66 20 2d 69 6d 20 65 78 70 6c 6f 72 65 72 2e 65 78 65 } //01 00 
		$a_01_1 = {73 74 61 72 74 2f 6d 61 78 20 68 74 74 70 3a 2f 2f 73 61 69 62 61 74 75 64 6f 6d 65 73 6d 6f 2e 62 6c 6f 67 73 70 6f 74 2e 63 6f 6d 2f } //01 00 
		$a_01_2 = {73 5c 53 79 73 74 65 6d 22 20 22 44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 22 20 22 31 22 } //00 00 
	condition:
		any of ($a_*)
 
}