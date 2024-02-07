
rule TrojanDownloader_Win32_Allaple_gen_B{
	meta:
		description = "TrojanDownloader:Win32/Allaple.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,1d 00 1d 00 08 00 00 0a 00 "
		
	strings :
		$a_01_0 = {46 61 73 74 4d 4d 20 42 6f 72 6c 61 6e 64 } //0a 00  FastMM Borland
		$a_03_1 = {6a ff 6a 00 e8 90 01 03 ff 8b d8 85 db 74 0c e8 90 01 03 ff 3d b7 00 00 00 75 0d 53 e8 90 00 } //01 00 
		$a_01_2 = {70 69 63 73 2f 64 65 66 61 75 6c 74 2f 69 72 73 5f } //01 00  pics/default/irs_
		$a_01_3 = {65 6d 61 69 6c 5f 64 6f 77 6e 6c 6f 61 64 65 72 } //01 00  email_downloader
		$a_01_4 = {57 69 6e 64 6f 77 73 20 4e 54 20 35 2e 31 3b 20 65 6e 3b 29 20 47 65 63 6b 6f 2f } //03 00  Windows NT 5.1; en;) Gecko/
		$a_01_5 = {69 72 73 5f 65 66 69 6c 6c 2e 70 68 70 00 55 8b } //03 00 
		$a_03_6 = {53 79 73 74 65 6d 52 6f 6f 74 00 00 65 78 70 6c 6f 72 65 72 20 68 74 74 70 3a 2f 2f 90 02 30 2e 70 64 66 90 00 } //03 00 
		$a_01_7 = {2e 70 64 66 00 00 ff ff ff ff 0c 00 00 00 5c 73 76 63 68 6f 73 74 2e 65 78 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}