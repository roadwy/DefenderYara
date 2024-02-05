
rule TrojanDownloader_Win32_Banload_BGP{
	meta:
		description = "TrojanDownloader:Win32/Banload.BGP,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {6f 00 70 00 65 00 6e 90 01 20 90 02 06 2e 00 76 00 62 00 73 90 00 } //0a 00 
		$a_03_1 = {68 70 11 01 00 e8 b7 ee f5 ff 6a 00 6a 00 6a 00 8d 45 8c e8 0d 8e ff ff ff 75 8c 68 90 01 03 00 68 90 01 03 00 68 90 01 03 00 68 90 01 03 00 68 90 01 03 00 68 90 01 03 00 68 90 01 03 00 6a 00 8d 45 90 90 ba 09 00 00 00 90 00 } //00 00 
		$a_00_2 = {5d 04 00 00 26 77 03 80 5c 22 } //00 00 
	condition:
		any of ($a_*)
 
}