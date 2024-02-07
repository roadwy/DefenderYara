
rule TrojanDownloader_Win32_Delf_TL{
	meta:
		description = "TrojanDownloader:Win32/Delf.TL,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //01 00  SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {61 6e 64 61 6d 69 72 6f 5f 69 6e 69 2e 69 6e 69 } //01 00  andamiro_ini.ini
		$a_01_2 = {72 75 6e 2e 69 6d 67 73 65 72 76 65 72 2e 6b 72 2f 63 6f 6e 66 69 67 2e 70 68 70 } //01 00  run.imgserver.kr/config.php
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_4 = {53 6f 66 74 77 61 72 65 5c 72 65 67 69 73 74 72 79 5f 61 64 6d 69 } //00 00  Software\registry_admi
	condition:
		any of ($a_*)
 
}