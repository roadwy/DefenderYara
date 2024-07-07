
rule Backdoor_Win32_Delf_ABA{
	meta:
		description = "Backdoor:Win32/Delf.ABA,SIGNATURE_TYPE_PEHSTR_EXT,3f 00 3e 00 0a 00 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //10 SOFTWARE\Borland\Delphi\RTL
		$a_00_1 = {68 61 63 6b 6d 65 } //10 hackme
		$a_00_2 = {74 67 67 6b 6f 6e 74 61 6b 74 } //10 tggkontakt
		$a_00_3 = {4b 4f 4e 54 41 4b 54 59 } //10 KONTAKTY
		$a_01_4 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //10 SetWindowsHookExA
		$a_00_5 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //10 UnhookWindowsHookEx
		$a_00_6 = {4e 75 6d 65 72 } //1 Numer
		$a_00_7 = {48 61 73 6c 6f } //1 Haslo
		$a_00_8 = {73 63 72 65 65 6e 2e 6a 70 67 } //1 screen.jpg
		$a_00_9 = {57 63 7a 79 74 61 6e 79 20 50 6c 69 6b 20 6a 65 73 74 20 6e 69 65 70 6f 70 72 61 77 6e 79 20 6c 75 62 20 62 72 61 6b 20 77 20 6e 69 6d 20 68 61 73 } //1 Wczytany Plik jest niepoprawny lub brak w nim has
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_01_4  & 1)*10+(#a_00_5  & 1)*10+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1) >=62
 
}