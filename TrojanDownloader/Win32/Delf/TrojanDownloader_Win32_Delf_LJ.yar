
rule TrojanDownloader_Win32_Delf_LJ{
	meta:
		description = "TrojanDownloader:Win32/Delf.LJ,SIGNATURE_TYPE_PEHSTR_EXT,2e 00 2e 00 0b 00 00 0a 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //0a 00  SOFTWARE\Borland\Delphi\RTL
		$a_00_1 = {43 61 72 72 65 67 61 6e 64 6f 20 2e 2e 2e } //0a 00  Carregando ...
		$a_00_2 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //0a 00  SetWindowsHookExA
		$a_00_3 = {47 65 74 4b 65 79 4e 61 6d 65 54 65 78 74 41 } //02 00  GetKeyNameTextA
		$a_02_4 = {68 74 74 70 3a 2f 2f 90 02 0f 2e 74 68 61 69 65 61 73 79 64 6e 73 2e 63 6f 6d 2f 90 02 15 6d 61 73 74 65 72 2e 74 78 74 90 00 } //01 00 
		$a_02_5 = {68 74 74 70 3a 2f 2f 90 02 0f 2e 73 65 72 76 65 66 74 70 2e 63 6f 6d 2f 90 02 15 6d 61 73 74 65 72 2e 74 78 74 90 00 } //01 00 
		$a_02_6 = {68 74 74 70 3a 2f 2f 90 02 0f 2e 73 65 72 76 65 66 74 70 2e 63 6f 6d 2f 90 02 20 63 6f 6e 74 61 64 6f 72 2e 70 68 70 90 00 } //01 00 
		$a_00_7 = {43 3a 5c 77 69 6e 64 6f 77 73 5c 77 69 6e 68 65 6c 70 33 32 2e 69 6e 69 } //01 00  C:\windows\winhelp32.ini
		$a_02_8 = {5c 4d 65 64 69 61 5c 90 02 08 2e 65 78 65 90 00 } //01 00 
		$a_02_9 = {5c 4d 65 64 69 61 5c 90 02 08 2e 63 70 6c 90 00 } //01 00 
		$a_00_10 = {5c 4d 65 64 69 61 5c 73 6d 73 73 2e 65 78 65 } //00 00  \Media\smss.exe
	condition:
		any of ($a_*)
 
}