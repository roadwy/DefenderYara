
rule PWS_Win32_Trickbot_N{
	meta:
		description = "PWS:Win32/Trickbot.N,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 72 61 62 5f 70 61 73 73 77 6f 72 64 73 5f 63 68 72 6f 6d 65 28 29 } //01 00 
		$a_01_1 = {66 72 6f 6d 20 6c 6f 67 69 6e 73 20 77 68 65 72 65 20 62 6c 61 63 6b 6c 69 73 74 65 64 5f 62 79 5f 75 73 65 72 20 3d 20 30 } //01 00 
		$a_01_2 = {5c 64 65 66 61 75 6c 74 5c 6c 6f 67 69 6e 20 64 61 74 61 2e 62 61 6b } //01 00 
		$a_01_3 = {6d 00 69 00 6d 00 69 00 6b 00 61 00 74 00 7a 00 } //00 00 
	condition:
		any of ($a_*)
 
}