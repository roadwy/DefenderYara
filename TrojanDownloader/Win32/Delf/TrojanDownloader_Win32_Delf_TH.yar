
rule TrojanDownloader_Win32_Delf_TH{
	meta:
		description = "TrojanDownloader:Win32/Delf.TH,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c } //01 00  SOFTWARE\Borland\Delphi\
		$a_01_1 = {43 6f 6d 6d 6f 6e 20 46 69 6c 65 73 5c 4d 61 63 72 6f 6d 65 64 69 61 5c 6e 76 64 69 61 76 62 2e 65 78 65 } //01 00  Common Files\Macromedia\nvdiavb.exe
		$a_01_2 = {43 6f 6d 6d 6f 6e 20 46 69 6c 65 73 5c 49 6e 73 74 61 6c 6c 53 68 69 65 6c 64 5c 45 6e 67 69 6e 65 5c 32 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 } //01 00  Common Files\InstallShield\Engine\2\iexplore.exe
		$a_01_3 = {6d 69 63 72 6f 73 6f 66 74 20 66 72 6f 6e 74 70 61 67 65 5c 76 65 72 73 69 6f 6e 32 2e 30 5c 62 69 6e 5c 6c 73 61 73 73 2e 65 78 65 } //01 00  microsoft frontpage\version2.0\bin\lsass.exe
		$a_01_4 = {6d 70 5f 66 69 6c 65 64 6f 77 6e 66 31 2e 70 68 70 3f 73 6e 3d } //01 00  mp_filedownf1.php?sn=
		$a_01_5 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //01 00  URLDownloadToFileA
		$a_01_6 = {75 72 6c 6d 6f 6e 2e 64 6c 6c } //00 00  urlmon.dll
	condition:
		any of ($a_*)
 
}