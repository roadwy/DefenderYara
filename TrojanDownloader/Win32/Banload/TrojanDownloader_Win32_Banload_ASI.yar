
rule TrojanDownloader_Win32_Banload_ASI{
	meta:
		description = "TrojanDownloader:Win32/Banload.ASI,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 00 72 00 6f 00 63 00 65 00 73 00 73 00 48 00 61 00 63 00 6b 00 65 00 72 00 } //01 00  ProcessHacker
		$a_01_1 = {66 00 69 00 6c 00 65 00 6d 00 6f 00 6e 00 2e 00 65 00 78 00 65 00 } //01 00  filemon.exe
		$a_01_2 = {73 00 6e 00 78 00 68 00 6b 00 } //01 00  snxhk
		$a_01_3 = {43 00 3a 00 5c 00 61 00 6e 00 61 00 6c 00 79 00 73 00 69 00 73 00 } //01 00  C:\analysis
		$a_01_4 = {28 00 42 00 72 00 61 00 73 00 69 00 6c 00 29 00 } //01 00  (Brasil)
		$a_01_5 = {50 00 65 00 6e 00 74 00 65 00 73 00 74 00 65 00 } //01 00  Penteste
		$a_01_6 = {77 00 69 00 6e 00 6d 00 67 00 6d 00 74 00 73 00 3a 00 5c 00 5c 00 25 00 73 00 5c 00 25 00 73 00 } //01 00  winmgmts:\\%s\%s
		$a_01_7 = {46 00 55 00 52 00 54 00 45 00 00 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 } //00 00 
		$a_00_8 = {5d 04 00 00 } //d0 ff 
	condition:
		any of ($a_*)
 
}