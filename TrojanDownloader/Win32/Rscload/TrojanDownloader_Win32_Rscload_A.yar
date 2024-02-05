
rule TrojanDownloader_Win32_Rscload_A{
	meta:
		description = "TrojanDownloader:Win32/Rscload.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {72 74 6c 61 73 79 76 71 } //01 00 
		$a_00_1 = {74 6b 62 71 62 68 6f 72 } //01 00 
		$a_02_2 = {b8 00 00 00 80 ff 74 24 64 88 1d 90 01 03 00 53 53 68 d8 01 00 00 68 17 01 00 00 50 50 68 00 00 08 00 68 90 01 03 00 68 90 01 03 00 68 00 02 00 00 ff 15 90 01 03 00 39 1d 90 01 03 00 8b f8 74 1c 39 1d 90 01 03 00 74 14 ff 35 90 01 03 00 56 68 90 01 03 00 e8 ab 01 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}