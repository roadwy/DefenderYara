
rule Trojan_Win32_Downloader_CO_MTB{
	meta:
		description = "Trojan:Win32/Downloader.CO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {43 3a 5c 54 45 4d 50 5c 73 65 74 75 70 2e 65 78 65 } //01 00  C:\TEMP\setup.exe
		$a_01_1 = {73 65 74 75 70 5f 69 6e 73 74 61 6c 6c 2e 65 78 65 } //01 00  setup_install.exe
		$a_81_2 = {25 73 25 53 2e 64 6c 6c } //01 00  %s%S.dll
		$a_01_3 = {21 40 49 6e 73 74 61 6c 6c 45 6e 64 40 21 37 7a } //01 00  !@InstallEnd@!7z
		$a_01_4 = {45 78 65 63 75 74 65 46 69 6c 65 } //01 00  ExecuteFile
		$a_01_5 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 } //01 00  GetTickCount
		$a_01_6 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //00 00  VirtualAlloc
	condition:
		any of ($a_*)
 
}