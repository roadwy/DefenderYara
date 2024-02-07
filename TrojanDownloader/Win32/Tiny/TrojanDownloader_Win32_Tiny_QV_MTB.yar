
rule TrojanDownloader_Win32_Tiny_QV_MTB{
	meta:
		description = "TrojanDownloader:Win32/Tiny.QV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_81_0 = {41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 77 6f 72 6d 2e 65 78 65 } //03 00  Application Data\worm.exe
		$a_81_1 = {41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 72 61 74 2e 65 78 65 } //03 00  Application Data\rat.exe
		$a_81_2 = {43 6f 64 69 6e 67 47 75 79 } //03 00  CodingGuy
		$a_81_3 = {44 52 4f 50 50 45 52 } //03 00  DROPPER
		$a_81_4 = {48 65 6c 70 4b 65 79 77 6f 72 64 41 74 74 72 69 62 75 74 65 } //03 00  HelpKeywordAttribute
		$a_81_5 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //03 00  DownloadString
		$a_81_6 = {67 65 74 5f 4e 65 74 77 6f 72 6b } //00 00  get_Network
	condition:
		any of ($a_*)
 
}