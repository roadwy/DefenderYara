
rule TrojanDownloader_Win32_Velowond_A{
	meta:
		description = "TrojanDownloader:Win32/Velowond.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {83 c6 02 53 68 90 01 04 8d 4d e8 89 75 c4 e8 90 01 04 8b f0 8d 4d e8 8d 7e 01 57 68 90 01 04 e8 90 01 04 8d 4d d4 89 45 10 e8 90 01 04 8d 4d d8 c6 45 fc 09 90 00 } //01 00 
		$a_01_1 = {25 74 65 6d 70 70 61 74 68 25 } //01 00 
		$a_01_2 = {25 77 69 6e 70 61 74 68 25 } //01 00 
		$a_01_3 = {25 73 79 73 74 65 6d 70 61 74 68 25 } //00 00 
	condition:
		any of ($a_*)
 
}