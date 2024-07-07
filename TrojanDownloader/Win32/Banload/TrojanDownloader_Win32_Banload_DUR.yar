
rule TrojanDownloader_Win32_Banload_DUR{
	meta:
		description = "TrojanDownloader:Win32/Banload.DUR,SIGNATURE_TYPE_PEHSTR,ffffff91 01 ffffff91 01 08 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 41 72 71 75 69 76 6f 73 20 64 65 20 70 72 6f 67 72 61 6d 61 73 5c 4d 69 63 72 6f 73 6f 66 74 20 56 69 73 75 61 6c 20 53 74 75 64 69 6f 5c } //100 C:\Arquivos de programas\Microsoft Visual Studio\
		$a_01_1 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //100 ShellExecuteA
		$a_01_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //100 URLDownloadToFileA
		$a_01_3 = {6e 00 65 00 74 00 73 00 68 00 20 00 66 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 20 00 61 00 64 00 64 00 20 00 61 00 6c 00 6c 00 6f 00 77 00 65 00 64 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 } //100 netsh firewall add allowedprogram
		$a_01_4 = {65 78 65 63 75 74 61 2e 21 21 21 } //1 executa.!!!
		$a_01_5 = {59 6f 75 54 75 62 65 } //1 YouTube
		$a_01_6 = {2e 00 73 00 63 00 72 00 } //1 .scr
		$a_01_7 = {2e 00 70 00 69 00 66 00 } //1 .pif
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100+(#a_01_2  & 1)*100+(#a_01_3  & 1)*100+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=401
 
}