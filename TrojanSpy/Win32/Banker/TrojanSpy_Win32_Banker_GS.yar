
rule TrojanSpy_Win32_Banker_GS{
	meta:
		description = "TrojanSpy:Win32/Banker.GS,SIGNATURE_TYPE_PEHSTR,29 00 29 00 08 00 00 "
		
	strings :
		$a_01_0 = {65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 62 00 61 00 72 00 } //10 explorerbar
		$a_01_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //10 URLDownloadToFileA
		$a_01_2 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 6d 73 69 65 78 70 6c 6f 72 65 72 2e 65 78 65 } //10 c:\windows\msiexplorer.exe
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //10 SOFTWARE\Borland\Delphi\RTL
		$a_01_4 = {68 71 5e 71 68 63 71 64 60 6d 73 71 63 } //1 hq^qhcqd`msqc
		$a_01_5 = {7a 5f 6d 68 72 67 5f 63 7a 69 63 6d 71 5e 66 6a 67 64 71 64 } //1 z_mhrg_czicmq^fjgdqd
		$a_01_6 = {68 74 74 70 3a 2f 2f 77 77 77 2e 63 61 69 78 61 2e 67 6f 76 2e 62 72 2f 56 6f 63 65 2f } //1 http://www.caixa.gov.br/Voce/
		$a_01_7 = {68 74 74 70 3a 2f 2f 6c 75 73 79 73 2e 6e 65 78 65 6e 73 65 72 76 69 63 65 73 2e 63 6f 6d 2f } //1 http://lusys.nexenservices.com/
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=41
 
}