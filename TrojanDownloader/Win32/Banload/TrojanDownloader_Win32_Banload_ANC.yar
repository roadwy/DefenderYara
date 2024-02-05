
rule TrojanDownloader_Win32_Banload_ANC{
	meta:
		description = "TrojanDownloader:Win32/Banload.ANC,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {75 08 8b 45 fc e8 90 01 04 a1 90 01 02 45 00 ba 90 01 02 45 00 e8 90 01 04 a1 90 01 02 45 00 b9 90 01 02 45 00 8b 55 fc 90 00 } //01 00 
		$a_02_1 = {50 72 6f 67 72 61 6d 44 61 74 61 5c 90 02 0a 68 74 74 70 3a 2f 2f 90 02 50 2e 7a 69 70 90 02 10 77 90 02 02 68 6f 73 74 2e 65 78 65 90 00 } //01 00 
		$a_02_2 = {50 72 6f 67 72 61 6d 44 61 74 61 5c 90 02 0a 68 74 74 70 3a 2f 2f 90 02 50 2e 62 6d 70 90 02 10 77 90 02 02 68 6f 73 74 2e 65 78 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}