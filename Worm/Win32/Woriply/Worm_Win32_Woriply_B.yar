
rule Worm_Win32_Woriply_B{
	meta:
		description = "Worm:Win32/Woriply.B,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 6d 63 76 73 73 68 6c 64 2e 65 78 65 } //01 00 
		$a_01_1 = {61 74 74 72 69 62 20 2b 68 20 66 74 70 63 6d 64 73 32 2e 74 78 74 } //01 00 
		$a_01_2 = {66 74 70 20 2d 73 3a 66 74 70 63 6d 64 73 2e 74 78 74 } //00 00 
	condition:
		any of ($a_*)
 
}