
rule TrojanDownloader_Win32_VBKrypt_HAZ_MTB{
	meta:
		description = "TrojanDownloader:Win32/VBKrypt.HAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {56 42 56 4d 36 30 2e 44 4c 4c } //1 VBVM60.DLL
		$a_01_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 73 75 6e 71 74 72 2e 63 6f 6d 2f 75 70 6c 6f 61 64 2f 77 68 5f 35 32 37 33 38 31 36 39 2e 65 78 65 } //1 http://www.sunqtr.com/upload/wh_52738169.exe
		$a_01_2 = {63 3a 5c 73 65 72 76 2e 65 78 65 } //1 c:\serv.exe
		$a_01_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_01_4 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //1 ShellExecuteA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}