
rule TrojanDownloader_Win32_Abcexp_A{
	meta:
		description = "TrojanDownloader:Win32/Abcexp.A,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 05 00 "
		
	strings :
		$a_00_0 = {77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 65 78 70 31 6f 72 65 72 2e 65 78 65 } //02 00  windows\system32\exp1orer.exe
		$a_00_1 = {32 31 37 2e 31 37 2e 34 31 2e 39 33 } //02 00  217.17.41.93
		$a_02_2 = {41 42 43 44 45 46 47 48 2e 65 78 65 90 01 0c 41 42 43 44 45 46 47 48 2e 65 78 65 90 00 } //01 00 
		$a_00_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  Software\Microsoft\Windows\CurrentVersion\Run
		$a_00_4 = {44 6f 73 43 6f 6d 6d 61 6e 64 31 4e 65 77 4c 69 6e 65 } //00 00  DosCommand1NewLine
	condition:
		any of ($a_*)
 
}