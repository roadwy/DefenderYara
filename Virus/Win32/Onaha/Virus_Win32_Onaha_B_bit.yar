
rule Virus_Win32_Onaha_B_bit{
	meta:
		description = "Virus:Win32/Onaha.B!bit,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {5c 48 61 6e 61 38 4f 2e 65 78 65 } //01 00  \Hana8O.exe
		$a_01_1 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } //01 00  \\.\PhysicalDrive0
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //02 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_03_3 = {81 e2 01 00 00 80 79 05 4a 83 ca fe 42 8a 90 01 02 08 75 05 80 f1 55 eb 03 80 f1 aa 88 90 01 02 08 40 3d fe 01 00 00 7c d7 90 00 } //01 00 
		$a_03_4 = {6a 00 6a 00 6a 00 6a 04 55 ff 15 90 01 02 40 00 8b f0 85 f6 0f 84 92 00 00 00 66 8b 06 66 3d 4d 5a 74 06 66 3d 5a 4d 75 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}