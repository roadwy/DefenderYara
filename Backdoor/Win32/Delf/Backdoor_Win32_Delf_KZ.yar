
rule Backdoor_Win32_Delf_KZ{
	meta:
		description = "Backdoor:Win32/Delf.KZ,SIGNATURE_TYPE_PEHSTR,4b 01 4b 01 0b 00 00 "
		
	strings :
		$a_01_0 = {65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 62 00 61 00 72 00 } //100 explorerbar
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //100 SOFTWARE\Borland\Delphi\RTL
		$a_01_2 = {77 69 6e 55 70 64 61 74 65 20 2d 20 4d 69 63 72 6f 73 6f 66 74 20 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 } //100 winUpdate - Microsoft Internet Explorer
		$a_01_3 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //10 SetWindowsHookExA
		$a_01_4 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //10 URLDownloadToFileA
		$a_01_5 = {49 6e 74 65 72 6e 65 74 47 65 74 43 6f 6e 6e 65 63 74 65 64 53 74 61 74 65 } //10 InternetGetConnectedState
		$a_01_6 = {5c 54 65 6d 70 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 } //1 \Temp\iexplore.exe
		$a_01_7 = {5c 54 65 6d 70 5c 6d 73 6e 2e 65 78 65 } //1 \Temp\msn.exe
		$a_01_8 = {5c 54 65 6d 70 5c 46 69 72 65 77 61 6c 6c 6c 2e 65 78 65 } //1 \Temp\Firewalll.exe
		$a_01_9 = {68 74 74 70 3a 2f 2f 77 77 77 2e 76 6f 78 63 61 72 64 73 2e 63 6f 6d 2e 62 72 } //1 http://www.voxcards.com.br
		$a_01_10 = {68 74 74 70 3a 2f 2f 66 65 6c 69 7a 32 30 30 38 2e 6c 61 6e 64 2e 72 75 2f 69 65 78 70 6c 6f 72 65 2e 65 78 65 } //1 http://feliz2008.land.ru/iexplore.exe
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100+(#a_01_2  & 1)*100+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=331
 
}