
rule Worm_Win32_Disnight_B{
	meta:
		description = "Worm:Win32/Disnight.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {4b 6e 69 67 68 74 2e 65 78 65 90 09 16 00 73 68 65 6c 6c 5c 65 78 70 6c 6f 72 65 5c 63 6f 6d 6d 61 6e 64 3d 90 00 } //01 00 
		$a_00_1 = {44 69 73 6b 20 4b 6e 69 67 68 74 } //01 00  Disk Knight
		$a_02_2 = {4b 6e 69 67 68 74 90 02 04 66 72 6d 4d 61 69 6e 90 02 04 6d 6f 64 50 72 6f 63 90 02 04 6d 6f 64 53 6d 61 72 74 48 6f 6f 6b 90 02 04 6d 6f 64 54 68 72 65 61 64 90 02 04 63 53 6d 61 72 74 48 6f 6f 6b 90 02 04 6d 6f 64 53 79 73 54 72 61 79 90 00 } //01 00 
		$a_00_3 = {5c 00 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00 } //00 00  \autorun.inf
	condition:
		any of ($a_*)
 
}