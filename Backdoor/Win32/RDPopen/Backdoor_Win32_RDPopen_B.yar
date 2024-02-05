
rule Backdoor_Win32_RDPopen_B{
	meta:
		description = "Backdoor:Win32/RDPopen.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 74 65 6d 50 25 00 63 73 72 73 73 72 2e 65 78 65 } //01 00 
		$a_01_1 = {57 69 6e 64 6f 77 2d 52 50 43 20 48 6f 73 2d 53 65 72 76 69 63 65 } //01 00 
		$a_02_2 = {2b c2 03 45 90 01 01 99 b9 1a 00 00 00 f7 f9 0f be 45 90 01 01 03 d0 8b 4d 90 01 01 88 11 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_RDPopen_B_2{
	meta:
		description = "Backdoor:Win32/RDPopen.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 06 6a 01 6a 02 8b 85 90 01 04 8b 88 84 01 00 00 ff d1 90 00 } //01 00 
		$a_03_1 = {ff d0 3d 33 27 00 00 75 90 01 01 6a 05 8b 4d 08 8b 91 24 01 00 00 ff d2 eb 90 01 01 33 c0 90 00 } //01 00 
		$a_00_2 = {7c 67 65 74 68 6f 73 74 6e 61 6d 65 } //01 00 
		$a_00_3 = {6a 69 65 66 68 68 66 75 66 68 } //01 00 
		$a_00_4 = {68 64 32 68 30 38 30 68 63 68 } //00 00 
	condition:
		any of ($a_*)
 
}