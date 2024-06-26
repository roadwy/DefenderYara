
rule PWS_Win32_Tibia_Q{
	meta:
		description = "PWS:Win32/Tibia.Q,SIGNATURE_TYPE_PEHSTR_EXT,30 00 30 00 0d 00 00 0a 00 "
		
	strings :
		$a_03_0 = {b8 b4 c2 76 00 e8 90 01 02 ff ff 8d 4d 90 01 01 8b 15 90 01 03 00 b8 94 c2 76 00 e8 90 01 02 ff ff 8b 15 90 01 03 00 b8 c8 c2 76 00 e8 90 01 02 ff ff 90 00 } //0a 00 
		$a_00_1 = {53 6f 66 74 77 61 72 65 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 4c 6f 63 61 6c 65 73 } //0a 00  Software\Borland\Delphi\Locales
		$a_00_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //0a 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_02_3 = {6c 6f 67 69 6e 90 02 02 2e 74 69 62 69 61 2e 63 6f 6d 90 00 } //01 00 
		$a_00_4 = {54 6f 6f 6c 68 65 6c 70 33 32 52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00  Toolhelp32ReadProcessMemory
		$a_00_5 = {74 69 62 69 61 2d 69 6e 6a 65 63 74 } //01 00  tibia-inject
		$a_00_6 = {64 6f 64 61 6a 2e 70 68 70 3f } //01 00  dodaj.php?
		$a_00_7 = {26 63 6f 6e 66 3d } //01 00  &conf=
		$a_00_8 = {26 61 63 63 3d } //01 00  &acc=
		$a_00_9 = {26 70 61 73 73 3d } //01 00  &pass=
		$a_00_10 = {26 6e 69 63 6b 3d } //01 00  &nick=
		$a_00_11 = {26 6c 76 6c 3d } //01 00  &lvl=
		$a_00_12 = {47 61 64 75 2d 47 61 64 75 } //00 00  Gadu-Gadu
	condition:
		any of ($a_*)
 
}