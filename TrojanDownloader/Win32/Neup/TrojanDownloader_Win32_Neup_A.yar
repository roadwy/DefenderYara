
rule TrojanDownloader_Win32_Neup_A{
	meta:
		description = "TrojanDownloader:Win32/Neup.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 02 00 "
		
	strings :
		$a_00_0 = {5c 73 73 70 69 33 32 2e 65 78 65 } //02 00  \sspi32.exe
		$a_00_1 = {25 73 5c 6e 65 77 75 70 2e 65 78 65 } //02 00  %s\newup.exe
		$a_01_2 = {53 68 65 6c 6c 00 00 00 45 78 65 63 75 00 00 00 74 65 41 00 } //01 00 
		$a_00_3 = {5c 69 65 76 65 72 73 69 6f 6e 2e 69 6e 69 00 } //01 00 
		$a_00_4 = {2f 2f 31 35 39 73 77 2e 63 6f 6d 2f } //01 00  //159sw.com/
		$a_00_5 = {00 67 67 5f 62 68 6f 00 } //01 00  最彧桢o
		$a_00_6 = {00 67 67 5f 73 70 69 00 } //00 00  最彧灳i
	condition:
		any of ($a_*)
 
}