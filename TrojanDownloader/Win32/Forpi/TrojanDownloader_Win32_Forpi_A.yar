
rule TrojanDownloader_Win32_Forpi_A{
	meta:
		description = "TrojanDownloader:Win32/Forpi.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 50 54 56 28 70 70 6c 69 76 65 29 5f 66 6f 72 } //01 00  PPTV(pplive)_for
		$a_01_1 = {5c 50 50 4c 69 76 65 } //01 00  \PPLive
		$a_01_2 = {64 6f 77 6e 6c 6f 61 64 2e 70 70 6c 69 76 65 2e 63 6f 6d } //01 00  download.pplive.com
		$a_01_3 = {4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 51 75 69 63 6b 20 4c 61 75 6e 63 68 5c 50 50 54 56 } //03 00  Microsoft\Internet Explorer\Quick Launch\PPTV
		$a_03_4 = {8b c0 53 33 db 6a 00 e8 90 01 04 83 f8 07 75 1c 6a 01 e8 90 01 04 25 00 ff 00 00 3d 00 0d 00 00 74 07 3d 00 04 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}