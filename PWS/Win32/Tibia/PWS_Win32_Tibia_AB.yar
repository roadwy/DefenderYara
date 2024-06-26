
rule PWS_Win32_Tibia_AB{
	meta:
		description = "PWS:Win32/Tibia.AB,SIGNATURE_TYPE_PEHSTR_EXT,2b 00 2a 00 08 00 00 01 00 "
		
	strings :
		$a_00_0 = {3f 6c 6f 67 69 6e 3d } //01 00  ?login=
		$a_00_1 = {26 70 61 73 73 } //01 00  &pass
		$a_03_2 = {70 61 73 73 77 6f 72 64 00 90 01 23 75 73 65 72 6e 61 6d 65 00 90 01 1b 50 61 73 73 77 6f 72 64 00 90 01 1b 55 73 65 72 6e 61 6d 65 00 90 00 } //0a 00 
		$a_00_3 = {74 69 62 69 61 } //0a 00  tibia
		$a_00_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //0a 00  Software\Microsoft\Windows\CurrentVersion\Run
		$a_00_5 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //0a 00  ReadProcessMemory
		$a_03_6 = {ff 0f 1f 00 e8 90 09 04 00 50 6a 00 68 90 00 } //f6 ff 
		$a_01_7 = {53 6f 66 74 77 61 72 65 5c 57 69 73 65 54 6f 70 5c 47 47 4c 6f 67 69 6e 43 6c 69 65 6e 74 00 } //00 00 
	condition:
		any of ($a_*)
 
}