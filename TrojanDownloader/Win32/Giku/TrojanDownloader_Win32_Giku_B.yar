
rule TrojanDownloader_Win32_Giku_B{
	meta:
		description = "TrojanDownloader:Win32/Giku.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 3b 45 08 72 12 8b 4d fc 8b 11 81 f2 90 01 04 8b 45 fc 89 10 eb dd 90 00 } //01 00 
		$a_03_1 = {73 18 8b 55 08 03 55 fc 0f be 02 35 90 01 04 8b 4d 08 03 4d fc 88 01 eb d7 90 00 } //01 00 
		$a_01_2 = {2f 74 65 70 2e 6a 70 67 } //01 00  /tep.jpg
		$a_01_3 = {5c 64 65 6c 6d 65 25 30 34 58 2e 62 61 74 } //00 00  \delme%04X.bat
	condition:
		any of ($a_*)
 
}