
rule PWS_Win32_Tibia_Q{
	meta:
		description = "PWS:Win32/Tibia.Q,SIGNATURE_TYPE_PEHSTR_EXT,30 00 30 00 0d 00 00 "
		
	strings :
		$a_03_0 = {b8 b4 c2 76 00 e8 ?? ?? ff ff 8d 4d ?? 8b 15 ?? ?? ?? 00 b8 94 c2 76 00 e8 ?? ?? ff ff 8b 15 ?? ?? ?? 00 b8 c8 c2 76 00 e8 ?? ?? ff ff } //10
		$a_00_1 = {53 6f 66 74 77 61 72 65 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 4c 6f 63 61 6c 65 73 } //10 Software\Borland\Delphi\Locales
		$a_00_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //10 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_02_3 = {6c 6f 67 69 6e [0-02] 2e 74 69 62 69 61 2e 63 6f 6d } //10
		$a_00_4 = {54 6f 6f 6c 68 65 6c 70 33 32 52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 Toolhelp32ReadProcessMemory
		$a_00_5 = {74 69 62 69 61 2d 69 6e 6a 65 63 74 } //1 tibia-inject
		$a_00_6 = {64 6f 64 61 6a 2e 70 68 70 3f } //1 dodaj.php?
		$a_00_7 = {26 63 6f 6e 66 3d } //1 &conf=
		$a_00_8 = {26 61 63 63 3d } //1 &acc=
		$a_00_9 = {26 70 61 73 73 3d } //1 &pass=
		$a_00_10 = {26 6e 69 63 6b 3d } //1 &nick=
		$a_00_11 = {26 6c 76 6c 3d } //1 &lvl=
		$a_00_12 = {47 61 64 75 2d 47 61 64 75 } //1 Gadu-Gadu
	condition:
		((#a_03_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_02_3  & 1)*10+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1+(#a_00_12  & 1)*1) >=48
 
}