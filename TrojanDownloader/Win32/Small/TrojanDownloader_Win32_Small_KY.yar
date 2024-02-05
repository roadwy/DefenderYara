
rule TrojanDownloader_Win32_Small_KY{
	meta:
		description = "TrojanDownloader:Win32/Small.KY,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 73 70 65 65 64 61 70 70 73 2e 63 6f 6d 2f 61 64 73 70 61 63 65 5f 62 63 5f 72 65 66 5f 31 2e 68 74 6d } //01 00 
		$a_03_1 = {8d 7e 74 6a 68 56 8b cf e8 90 01 02 ff ff 68 90 01 02 40 00 8d 4c 24 14 e8 90 01 02 00 00 8b 44 90 01 02 8b cf 50 c7 84 90 01 03 00 00 00 00 00 00 e8 90 01 02 ff ff 8d 4c 90 01 02 68 08 02 00 00 51 6a 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}