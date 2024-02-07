
rule TrojanDownloader_Win32_Banload_BFY{
	meta:
		description = "TrojanDownloader:Win32/Banload.BFY,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 6d 72 56 65 72 66 54 69 6d 65 72 } //01 00  tmrVerfTimer
		$a_01_1 = {74 6d 72 42 61 69 78 61 54 69 6d 65 72 } //01 00  tmrBaixaTimer
		$a_01_2 = {78 2e 67 69 66 } //01 00  x.gif
		$a_01_3 = {75 4d 6f 64 41 76 73 } //01 00  uModAvs
		$a_03_4 = {b9 03 00 00 00 33 d2 e8 90 01 03 ff ff 75 e8 68 90 01 02 47 00 8b 45 fc 05 0c 03 00 00 ba 03 00 00 00 e8 90 01 02 f8 ff 90 00 } //00 00 
		$a_00_5 = {80 10 00 } //00 fd 
	condition:
		any of ($a_*)
 
}