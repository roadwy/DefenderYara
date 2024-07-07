
rule TrojanDownloader_Win32_Delf_BL{
	meta:
		description = "TrojanDownloader:Win32/Delf.BL,SIGNATURE_TYPE_PEHSTR,13 02 12 02 0c 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //100 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //100 DllRegisterServer
		$a_01_2 = {65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 62 00 61 00 72 00 } //100 explorerbar
		$a_01_3 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 49 00 6e 00 63 00 2e 00 } //100 Microsoft Inc.
		$a_01_4 = {77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 2d 00 75 00 70 00 64 00 61 00 74 00 65 00 } //100 windows-update
		$a_01_5 = {57 53 41 43 6f 6e 6e 65 63 74 } //10 WSAConnect
		$a_01_6 = {54 72 61 6e 73 6d 69 74 46 69 6c 65 } //10 TransmitFile
		$a_01_7 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 65 78 70 6c 6f 72 65 72 5c 42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 5c } //10 Software\Microsoft\Windows\CurrentVersion\explorer\Browser Helper Objects\
		$a_01_8 = {61 64 69 6f 6e 61 6c 63 6f 6f 2e 69 6e 69 } //1 adionalcoo.ini
		$a_01_9 = {52 65 67 73 76 72 33 32 2e 65 78 65 20 2f 73 20 } //1 Regsvr32.exe /s 
		$a_01_10 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6f 68 32 33 34 35 2e 63 6e } //1 http://www.oh2345.cn
		$a_01_11 = {68 74 74 70 3a 2f 2f 77 77 77 2e 69 6e 66 6f 33 33 34 34 2e 63 6e } //1 http://www.info3344.cn
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100+(#a_01_2  & 1)*100+(#a_01_3  & 1)*100+(#a_01_4  & 1)*100+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10+(#a_01_7  & 1)*10+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=530
 
}