
rule TrojanDownloader_Win32_Banload_OG{
	meta:
		description = "TrojanDownloader:Win32/Banload.OG,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {5c 00 6e 00 65 00 77 00 5f 00 73 00 65 00 6e 00 64 00 2e 00 76 00 62 00 70 00 } //01 00 
		$a_03_1 = {6a 2e 8d 8d 90 01 02 ff ff 51 ff 15 90 01 04 6a 63 8d 95 90 01 02 ff ff 52 ff 15 90 01 04 6a 6f 8d 85 90 01 02 ff ff 50 ff 15 90 01 04 6a 6d 8d 8d 90 01 02 ff ff 51 ff 15 90 01 04 6a 2e 8d 95 90 01 02 ff ff 52 ff 15 90 01 04 6a 62 8d 85 90 01 02 ff ff 50 ff 15 90 01 04 6a 72 90 00 } //02 00 
		$a_03_2 = {6a 2e 51 ff d6 8d 90 01 03 ff ff 6a 43 52 ff d6 8d 90 01 03 ff ff 6a 65 50 ff d6 8d 90 01 03 ff ff 6a 6e 51 ff d6 8d 90 01 03 ff ff 6a 74 52 ff d6 8d 90 01 03 ff ff 6a 65 50 ff d6 8d 90 01 03 ff ff 6a 72 51 ff d6 8d 90 01 03 ff ff 6a 50 52 ff d6 8d 90 01 03 ff ff 6a 6c 50 ff d6 8d 90 01 03 ff ff 6a 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}