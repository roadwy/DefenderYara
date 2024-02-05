
rule Worm_Win32_Tifi_B_dr{
	meta:
		description = "Worm:Win32/Tifi.B!dr,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 68 65 6c 6c 65 78 65 63 75 74 65 3d 57 73 63 72 69 70 74 2e 65 78 65 20 2f 65 3a 76 62 73 20 44 61 6c 69 66 69 74 2e 6a 70 67 } //01 00 
		$a_01_1 = {66 6c 61 73 68 64 72 69 76 65 2e 70 61 74 68 20 26 22 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 } //00 00 
	condition:
		any of ($a_*)
 
}