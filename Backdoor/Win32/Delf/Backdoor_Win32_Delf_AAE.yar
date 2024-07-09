
rule Backdoor_Win32_Delf_AAE{
	meta:
		description = "Backdoor:Win32/Delf.AAE,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //1 SOFTWARE\Borland\Delphi\RTL
		$a_00_1 = {43 3a 5c 73 6b 72 69 6e 2e 6a 70 67 } //1 C:\skrin.jpg
		$a_00_2 = {43 3a 5c 68 6f 73 74 5c 6c 6f 67 2e 74 78 74 } //1 C:\host\log.txt
		$a_00_3 = {63 3a 5c 70 6c 69 6b 2e 65 78 65 } //1 c:\plik.exe
		$a_00_4 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 73 76 68 6f 73 74 65 64 2e 65 78 65 } //1 C:\Windows\svhosted.exe
		$a_00_5 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_00_6 = {54 65 6b 73 74 20 77 20 53 63 68 6f 77 6b 75 3a } //1 Tekst w Schowku:
		$a_02_7 = {6a 00 6a 00 49 75 f9 53 89 45 fc bb ?? ?? 49 00 33 c0 55 68 ?? ?? 48 00 64 ff 30 64 89 20 6a 00 a1 64 f6 48 00 50 68 ?? ?? 48 00 6a 00 e8 ?? ?? f7 ff a3 ?? ?? 49 00 a1 ?? ?? 48 00 8b 00 c6 40 5b 00 6a ff 68 ?? ?? 48 00 8d 55 f8 33 c0 e8 ?? ?? f7 ff 8b 45 f8 e8 ?? ?? f7 ff 50 e8 ?? ?? f7 ff 8d 55 f4 } //1
		$a_02_8 = {8b 45 ac ba 02 00 00 00 e8 ?? ?? f7 ff 68 ?? ?? 48 00 8d 55 a0 33 c0 e8 ?? ?? f7 ff 8b 45 a0 e8 ?? ?? f7 ff 50 e8 ?? ?? f7 ff b2 01 a1 ?? ?? 42 00 e8 ?? ?? f9 ff a3 ?? ?? 49 00 ba 02 00 00 80 a1 ?? ?? 49 00 e8 ?? ?? f9 ff 33 c0 55 68 ?? ?? 48 00 64 ff 30 64 89 20 b1 01 ba ?? ?? 48 00 a1 ?? ?? 49 00 e8 ?? ?? f9 ff 68 ?? ?? 48 00 8d 55 98 8b 45 fc 8b 80 2c 03 00 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_02_7  & 1)*1+(#a_02_8  & 1)*1) >=9
 
}