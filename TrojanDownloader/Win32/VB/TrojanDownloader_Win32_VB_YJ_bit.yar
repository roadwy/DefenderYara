
rule TrojanDownloader_Win32_VB_YJ_bit{
	meta:
		description = "TrojanDownloader:Win32/VB.YJ!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {2a 54 44 53 2a 90 02 10 2a 54 44 53 2a 90 00 } //01 00 
		$a_01_1 = {53 65 63 75 72 69 74 79 5f 44 6f 77 6e 6c 6f 61 64 65 72 00 73 6b 74 6f 00 } //01 00 
		$a_01_2 = {5c 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 20 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 65 00 72 00 5c 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 5f 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 65 00 72 00 2e 00 76 00 62 00 70 00 } //01 00  \Security Downloader\Security_Downloader.vbp
		$a_03_3 = {8d 55 a4 8d 4d c4 c7 45 ac 80 17 40 00 c7 45 a4 08 00 00 00 e8 90 01 02 ff ff 56 8d 45 c4 6a ff 50 ff 75 e8 8d 45 b4 50 e8 90 01 02 ff ff 90 00 } //00 00 
		$a_00_4 = {5d 04 00 } //00 08 
	condition:
		any of ($a_*)
 
}