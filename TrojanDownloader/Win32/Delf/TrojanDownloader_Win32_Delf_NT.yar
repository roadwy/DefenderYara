
rule TrojanDownloader_Win32_Delf_NT{
	meta:
		description = "TrojanDownloader:Win32/Delf.NT,SIGNATURE_TYPE_PEHSTR,1f 00 1f 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 42 00 6f 00 72 00 6c 00 61 00 6e 00 64 00 5c 00 44 00 65 00 6c 00 70 00 68 00 69 00 5c 00 4c 00 6f 00 63 00 61 00 6c 00 65 00 73 00 } //0a 00  Software\Borland\Delphi\Locales
		$a_01_1 = {43 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 2d 00 54 00 79 00 70 00 65 00 3a 00 20 00 61 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 2f 00 78 00 2d 00 77 00 77 00 77 00 2d 00 66 00 6f 00 72 00 6d 00 2d 00 75 00 72 00 6c 00 65 00 6e 00 63 00 6f 00 64 00 65 00 64 00 } //0a 00  Content-Type: application/x-www-form-urlencoded
		$a_01_2 = {6a 00 70 00 64 00 65 00 73 00 6b 00 } //01 00  jpdesk
		$a_01_3 = {35 00 38 00 2e 00 32 00 35 00 33 00 2e 00 32 00 33 00 35 00 2e 00 38 00 } //01 00  58.253.235.8
		$a_01_4 = {64 00 6c 00 5f 00 64 00 69 00 72 00 32 00 2e 00 71 00 71 00 2e 00 63 00 6f 00 6d 00 } //00 00  dl_dir2.qq.com
	condition:
		any of ($a_*)
 
}