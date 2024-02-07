
rule TrojanDownloader_Win32_Banload_AVQ{
	meta:
		description = "TrojanDownloader:Win32/Banload.AVQ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 63 00 68 00 72 00 69 00 73 00 2e 00 74 00 78 00 74 00 } //01 00  C:\Windows\chris.txt
		$a_01_1 = {63 6d 64 20 2f 63 20 73 74 61 72 74 20 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 61 75 74 68 64 2e 63 70 6c } //01 00  cmd /c start C:\ProgramData\authd.cpl
		$a_01_2 = {63 6d 64 20 2f 63 20 73 74 61 72 74 20 43 3a 5c 41 52 51 55 49 56 7e 31 5c 32 36 2e 63 70 6c } //01 00  cmd /c start C:\ARQUIV~1\26.cpl
		$a_01_3 = {63 6d 64 20 2f 63 20 73 74 61 72 74 20 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 37 36 2e 63 70 6c } //01 00  cmd /c start C:\ProgramData\76.cpl
		$a_01_4 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 46 00 69 00 6c 00 65 00 73 00 5c 00 37 00 36 00 2e 00 63 00 70 00 6c 00 } //00 00  C:\Program Files\76.cpl
	condition:
		any of ($a_*)
 
}