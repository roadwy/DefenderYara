
rule Virus_Win32_Delf_F{
	meta:
		description = "Virus:Win32/Delf.F,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {46 69 6c 65 20 46 6f 6c 64 65 72 } //1 File Folder
		$a_01_1 = {65 78 70 6c 6f 72 65 72 } //1 explorer
		$a_01_2 = {68 68 3a 6e 6e } //1 hh:nn
		$a_01_3 = {61 74 20 25 73 20 63 6d 64 20 2f 63 20 64 65 6c 20 22 25 73 22 } //1 at %s cmd /c del "%s"
		$a_01_4 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 76 63 68 6f 73 74 2e 65 78 65 } //1 C:\WINDOWS\svchost.exe
		$a_01_5 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 76 63 68 6f 73 74 2e 64 6c 6c } //1 C:\WINDOWS\svchost.dll
		$a_01_6 = {61 74 20 25 73 20 25 73 20 66 69 72 65 77 61 6c 6c } //1 at %s %s firewall
		$a_01_7 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //1 SOFTWARE\Borland\Delphi\RTL
		$a_01_8 = {46 69 6e 64 4e 65 78 74 46 69 6c 65 41 } //1 FindNextFileA
		$a_01_9 = {46 69 6e 64 46 69 72 73 74 46 69 6c 65 41 } //1 FindFirstFileA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}