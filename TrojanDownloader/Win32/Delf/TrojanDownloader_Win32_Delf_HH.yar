
rule TrojanDownloader_Win32_Delf_HH{
	meta:
		description = "TrojanDownloader:Win32/Delf.HH,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 72 69 70 74 2e 64 6c 6c } //1 cript.dll
		$a_01_1 = {77 69 6e 64 2e 69 6e 69 } //1 wind.ini
		$a_01_2 = {43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e 5c 4e 6f 74 69 66 79 5c 20 61 47 62 50 6c 75 67 69 6e } //1 CurrentVersion\Winlogon\Notify\ aGbPlugin
		$a_01_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}