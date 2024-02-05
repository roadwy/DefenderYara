
rule Backdoor_Win32_Littlemetp_B_{
	meta:
		description = "Backdoor:Win32/Littlemetp.B!!Littlemetp.B,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {56 89 75 fc ff d3 a1 90 01 04 6a 40 68 00 10 00 00 83 c0 05 50 90 02 06 ff 15 90 00 } //02 00 
		$a_03_1 = {c7 45 fc 80 33 00 00 50 6a 1f 56 ff 15 90 01 04 53 53 53 53 56 ff 15 90 01 04 85 c0 75 07 68 90 01 04 eb 90 01 01 6a 40 68 00 10 00 00 68 00 00 40 00 53 ff 15 90 00 } //01 00 
		$a_03_2 = {83 c4 0c a3 90 01 03 00 ff d0 90 00 } //05 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Littlemetp_B__2{
	meta:
		description = "Backdoor:Win32/Littlemetp.B!!Littlemetp.B,SIGNATURE_TYPE_ARHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 65 74 74 69 6e 67 20 74 68 65 20 66 69 6c 65 6e 61 6d 65 20 74 6f 20 22 32 5f 68 6f 73 74 2e 63 6f 6d 5f 34 34 33 2e 65 78 65 22 20 61 6e 64 20 72 75 6e 6e 69 6e 67 20 69 74 20 77 69 74 68 6f 75 74 20 61 72 67 73 20 77 69 6c 6c 20 64 6f 20 65 78 61 63 74 6c 79 20 74 68 65 20 73 61 6d 65 } //01 00 
		$a_00_1 = {33 3a 20 62 69 6e 64 5f 74 63 70 } //01 00 
		$a_00_2 = {6c 69 6b 65 20 54 52 41 4e 53 50 4f 52 54 5f 4c 48 4f 53 54 5f 4c 50 4f 52 54 2e 65 78 65 } //01 00 
		$a_00_3 = {74 69 6e 79 6d 65 74 2e 65 78 65 } //05 00 
	condition:
		any of ($a_*)
 
}