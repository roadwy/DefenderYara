
rule TrojanDownloader_Win32_Onitab_A{
	meta:
		description = "TrojanDownloader:Win32/Onitab.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 } //02 00 
		$a_01_1 = {5c 44 65 62 75 67 73 2e 69 6e 66 } //02 00 
		$a_01_2 = {21 40 23 24 72 23 40 25 40 23 24 40 23 } //00 00 
	condition:
		any of ($a_*)
 
}