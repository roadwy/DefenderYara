
rule Worm_Win32_Autorun_XF{
	meta:
		description = "Worm:Win32/Autorun.XF,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 6d 73 6e 2e 63 6f 6d } //01 00 
		$a_01_1 = {73 68 65 6c 6c 65 78 65 63 75 74 65 3d 61 75 74 6f 72 75 6e 2e 65 78 65 } //01 00 
		$a_01_2 = {61 73 64 66 5f 31 00 69 6e 65 74 5f 31 00 75 70 64 74 5f 31 } //01 00 
		$a_01_3 = {57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //00 00 
	condition:
		any of ($a_*)
 
}