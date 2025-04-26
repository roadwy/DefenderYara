
rule TrojanDownloader_Win32_VB_NI{
	meta:
		description = "TrojanDownloader:Win32/VB.NI,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {79 6f 75 74 75 62 65 76 69 64 65 6f 73 } //1 youtubevideos
		$a_01_1 = {4d 61 73 74 65 72 00 00 66 75 6e 63 6f 65 73 } //1
		$a_00_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_00_3 = {49 6e 74 65 72 6e 65 74 47 65 74 43 6f 6e 6e 65 63 74 65 64 53 74 61 74 65 } //1 InternetGetConnectedState
		$a_01_4 = {4d 00 6f 00 64 00 65 00 6d 00 00 00 0a 00 00 00 50 00 72 00 6f 00 78 00 79 00 } //1
		$a_00_5 = {43 00 6f 00 6e 00 66 00 69 00 67 00 75 00 72 00 61 00 64 00 61 00 } //1 Configurada
		$a_00_6 = {52 00 65 00 6d 00 6f 00 74 00 61 00 } //1 Remota
		$a_00_7 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //1 MSVBVM60.DLL
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=8
 
}