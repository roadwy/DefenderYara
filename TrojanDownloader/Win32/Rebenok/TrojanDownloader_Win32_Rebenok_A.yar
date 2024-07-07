
rule TrojanDownloader_Win32_Rebenok_A{
	meta:
		description = "TrojanDownloader:Win32/Rebenok.A,SIGNATURE_TYPE_PEHSTR,29 00 29 00 08 00 00 "
		
	strings :
		$a_01_0 = {25 73 25 69 74 6d 70 2e 65 78 65 } //10 %s%itmp.exe
		$a_01_1 = {62 6f 74 5f 6d 61 69 6e 28 29 } //10 bot_main()
		$a_01_2 = {68 74 74 70 3a 2f 2f 62 6f 74 3a } //10 http://bot:
		$a_01_3 = {68 74 74 70 5f 64 6f 77 6e 6c 6f 61 64 28 29 } //10 http_download()
		$a_01_4 = {61 6e 74 69 64 65 62 75 67 5f 64 65 74 65 63 74 64 65 62 75 67 67 65 72 28 29 } //10 antidebug_detectdebugger()
		$a_01_5 = {25 73 25 73 25 73 25 73 20 75 6e 61 62 6c 65 20 74 6f 20 6b 69 6c 6c 20 25 73 74 68 72 65 61 64 3a 25 73 20 25 69 21 } //10 %s%s%s%s unable to kill %sthread:%s %i!
		$a_01_6 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //1 KeServiceDescriptorTable
		$a_01_7 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=41
 
}