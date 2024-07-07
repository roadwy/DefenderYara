
rule TrojanDownloader_Win32_Delf_ZXC{
	meta:
		description = "TrojanDownloader:Win32/Delf.ZXC,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 08 00 00 "
		
	strings :
		$a_02_0 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 65 73 5c 00 90 02 10 00 68 74 74 70 3a 2f 2f 90 02 20 2e 6a 70 67 00 90 02 10 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 65 73 5c 90 02 10 2e 65 78 65 00 90 00 } //4
		$a_00_1 = {63 6d 64 20 2f 6b 20 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 65 73 5c 4d 61 6e 61 67 65 57 69 6e 2e 65 78 65 } //1 cmd /k C:\ProgramDates\ManageWin.exe
		$a_00_2 = {63 6d 64 20 2f 6b 20 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 65 73 5c 53 79 73 74 65 6d 4f 70 65 72 61 2e 65 78 65 } //1 cmd /k C:\ProgramDates\SystemOpera.exe
		$a_00_3 = {63 6d 64 20 2f 6b 20 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 65 73 5c 73 79 73 75 70 74 61 64 2e 65 78 65 } //1 cmd /k C:\ProgramDates\sysuptad.exe
		$a_00_4 = {68 74 74 70 3a 2f 2f 66 69 72 65 73 74 77 65 62 2e 63 6f 6d 2f 6c 6f 6a 61 2f 73 6f 63 69 61 6c 2f 31 2e 6a 70 67 } //1 http://firestweb.com/loja/social/1.jpg
		$a_00_5 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6e 65 72 64 64 6f 67 75 65 74 6f 2e 63 6f 6d 2e 62 72 } //1 http://www.nerddogueto.com.br
		$a_00_6 = {68 74 74 70 3a 2f 2f 66 69 72 65 73 74 77 65 62 2e 63 6f 6d 2f 6c 6f 6a 61 2f 73 6f 63 69 61 6c 2f 32 2e 6a 70 67 } //1 http://firestweb.com/loja/social/2.jpg
		$a_00_7 = {68 74 74 70 3a 2f 2f 66 69 72 65 73 74 77 65 62 2e 63 6f 6d 2f 6c 6f 6a 61 2f 73 6f 63 69 61 6c 2f 33 2e 6a 70 67 } //1 http://firestweb.com/loja/social/3.jpg
	condition:
		((#a_02_0  & 1)*4+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=6
 
}