
rule PWS_Win32_OnLineGames_B{
	meta:
		description = "PWS:Win32/OnLineGames.B,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 43 6e 39 31 31 5c 45 78 70 6c 6f 72 65 72 5c 52 75 6e } //1 SOFTWARE\Cn911\Explorer\Run
		$a_00_1 = {52 55 4e 4a 55 53 6b 43 45 2e 42 41 54 } //1 RUNJUSkCE.BAT
		$a_00_2 = {26 47 61 6d 65 50 61 73 73 43 61 72 64 3d } //1 &GamePassCard=
		$a_00_3 = {4d 6f 6e 65 79 } //1 Money
		$a_00_4 = {45 6c 65 6d 65 6e 74 43 6c 69 65 6e 74 20 57 69 6e 64 6f 77 } //1 ElementClient Window
		$a_00_5 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_01_6 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 41 } //1 InternetOpenA
		$a_00_7 = {73 00 63 00 72 00 6e 00 73 00 61 00 76 00 65 00 2e 00 65 00 78 00 65 00 } //1 scrnsave.exe
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_01_6  & 1)*1+(#a_00_7  & 1)*1) >=8
 
}