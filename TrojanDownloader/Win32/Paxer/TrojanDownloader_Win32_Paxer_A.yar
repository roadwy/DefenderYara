
rule TrojanDownloader_Win32_Paxer_A{
	meta:
		description = "TrojanDownloader:Win32/Paxer.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 46 20 65 78 69 73 74 20 22 25 73 22 20 47 4f 54 4f 20 41 41 41 } //01 00  IF exist "%s" GOTO AAA
		$a_01_1 = {49 46 20 65 78 69 73 74 20 22 25 73 22 20 47 4f 54 4f 20 42 42 42 } //01 00  IF exist "%s" GOTO BBB
		$a_01_2 = {63 6f 6e 74 65 6e 74 2e 64 61 74 } //01 00  content.dat
		$a_03_3 = {66 6c 61 73 68 70 6c 61 79 65 72 5f 90 02 10 2e 65 78 65 00 90 00 } //01 00 
		$a_01_4 = {25 73 5c 64 65 6c 65 74 65 6d 65 2e 62 61 74 } //01 00  %s\deleteme.bat
		$a_01_5 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 53 68 61 72 65 00 } //00 00 
		$a_00_6 = {5d 04 00 } //00 b4 
	condition:
		any of ($a_*)
 
}