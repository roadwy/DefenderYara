
rule Worm_Win32_Stekct_A{
	meta:
		description = "Worm:Win32/Stekct.A,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_00_0 = {59 61 68 6f 6f 42 75 64 64 79 4d 61 69 6e } //03 00  YahooBuddyMain
		$a_00_1 = {6d 73 67 5f 69 64 3d 25 69 26 63 6c 69 65 6e 74 5f 74 69 6d 65 3d 25 69 26 74 6f 3d 25 73 } //03 00  msg_id=%i&client_time=%i&to=%s
		$a_02_2 = {4d 73 4d 70 45 6e 67 2e 65 78 65 90 02 20 65 67 75 69 2e 65 78 65 90 00 } //01 00 
		$a_03_3 = {6a 00 6a 00 6a 00 6a 25 ff d6 6a 00 6a 00 6a 00 6a 26 ff d6 33 d2 8b c5 b9 05 00 00 00 f7 f1 85 d2 75 04 6a 01 ff d7 45 81 fd 90 01 02 00 00 7c d0 90 00 } //01 00 
		$a_03_4 = {53 53 53 6a 25 ff d6 53 53 53 6a 26 ff d6 8b 44 24 90 01 01 6a 05 99 59 f7 f9 85 d2 75 04 6a 01 ff d7 ff 44 24 90 01 01 81 7c 24 90 01 03 00 00 7c d2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}