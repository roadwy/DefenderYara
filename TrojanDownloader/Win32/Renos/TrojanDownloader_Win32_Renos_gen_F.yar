
rule TrojanDownloader_Win32_Renos_gen_F{
	meta:
		description = "TrojanDownloader:Win32/Renos.gen!F,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 72 65 20 79 6f 75 20 73 75 72 65 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 75 6e 69 6e 73 74 61 6c 6c 20 57 69 6e 64 6f 77 73 20 53 61 66 65 74 79 20 41 6c 65 72 74 20 66 72 6f 6d 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 3f } //01 00  Are you sure you want to uninstall Windows Safety Alert from your computer?
		$a_01_1 = {50 6c 65 61 73 65 20 77 61 69 74 20 77 68 69 6c 65 20 57 69 6e 64 6f 77 73 20 53 61 66 65 74 79 20 41 6c 65 72 74 20 69 73 20 62 65 69 6e 67 20 75 6e 69 6e 73 74 61 6c 6c 65 64 2e 20 43 6c 6f 73 65 20 61 6c 6c 20 61 70 70 6c 69 63 61 74 69 6f 6e 73 2e } //01 00  Please wait while Windows Safety Alert is being uninstalled. Close all applications.
		$a_00_2 = {54 68 69 73 20 70 72 6f 67 72 61 6d 20 69 6e 73 74 61 6c 6c 20 6f 6e 20 79 6f 75 72 20 73 79 73 74 65 6d 20 61 6e 74 69 73 70 61 79 77 61 72 65 20 73 6f 66 74 77 61 72 65 2e } //01 00  This program install on your system antispayware software.
		$a_00_3 = {63 61 72 6f 6c 75 73 } //01 00  carolus
		$a_00_4 = {2f 63 20 64 65 6c 20 25 73 20 3e 3e 20 4e 55 4c 4c } //01 00  /c del %s >> NULL
		$a_01_5 = {78 79 78 75 69 63 2e 64 6c 6c } //01 00  xyxuic.dll
		$a_01_6 = {70 6b 67 76 79 67 2e 64 6c 6c } //01 00  pkgvyg.dll
		$a_01_7 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c 5c 57 69 6e 64 6f 77 73 20 53 61 66 65 74 79 20 41 6c 65 72 74 } //01 00  Software\Microsoft\Windows\CurrentVersion\Uninstall\Windows Safety Alert
		$a_00_8 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 2c 77 69 6e 64 6f 77 73 } //01 00  rundll32.exe %s,windows
		$a_00_9 = {53 59 53 52 45 53 } //00 00  SYSRES
	condition:
		any of ($a_*)
 
}