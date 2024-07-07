
rule Worm_Win32_Hamtacker_A{
	meta:
		description = "Worm:Win32/Hamtacker.A,SIGNATURE_TYPE_PEHSTR,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //1 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {50 68 6f 6e 65 4e 75 6d 62 65 72 3d } //1 PhoneNumber=
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 57 69 6e 41 46 43 52 } //1 SOFTWARE\WinAFCR
		$a_01_3 = {48 6f 73 74 20 66 69 6c 65 20 6c 6f 61 64 65 64 20 6f 6b } //1 Host file loaded ok
		$a_01_4 = {64 69 61 6c 73 79 73 2e 65 78 65 } //1 dialsys.exe
		$a_01_5 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_6 = {50 4f 50 33 20 53 65 72 76 65 72 } //1 POP3 Server
		$a_01_7 = {53 4d 54 50 20 53 65 72 76 65 72 } //1 SMTP Server
		$a_01_8 = {74 68 69 73 20 69 73 20 6e 6f 74 20 61 20 6d 61 72 6b 2c 20 69 73 20 61 20 63 68 65 61 74 } //1 this is not a mark, is a cheat
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}