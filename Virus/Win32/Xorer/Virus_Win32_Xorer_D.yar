
rule Virus_Win32_Xorer_D{
	meta:
		description = "Virus:Win32/Xorer.D,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 02 00 "
		
	strings :
		$a_02_0 = {81 c4 7c 44 00 00 c2 10 00 68 90 01 04 6a 01 6a 00 ff 15 90 01 04 ff 15 90 01 04 3d b7 00 00 00 75 12 5f 5e 5d b8 01 00 00 00 5b 81 c4 7c 44 00 00 c2 10 00 90 00 } //02 00 
		$a_00_1 = {63 73 00 00 63 00 00 00 5c 00 00 00 65 78 65 00 73 73 2e 00 6d 5c 00 00 } //01 00 
		$a_00_2 = {78 63 6e 62 6b 6a 77 65 72 } //01 00  xcnbkjwer
		$a_00_3 = {4d 53 49 43 54 46 49 4d 45 20 53 4d 53 53 } //01 00  MSICTFIME SMSS
		$a_00_4 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_00_5 = {4d 43 49 20 50 72 6f 67 72 61 6d 20 43 6f 6d 20 41 70 70 6c 69 63 61 74 69 6f 6e } //01 00  MCI Program Com Application
		$a_01_6 = {00 58 4f 52 00 } //00 00 
	condition:
		any of ($a_*)
 
}