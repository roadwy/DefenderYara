
rule TrojanDownloader_Win32_VB_GN{
	meta:
		description = "TrojanDownloader:Win32/VB.GN,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {13 00 00 00 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 00 } //01 00 
		$a_00_1 = {20 00 67 00 6f 00 74 00 6f 00 20 00 64 00 6c 00 6f 00 6f 00 70 00 } //01 00 
		$a_00_2 = {69 00 66 00 20 00 65 00 78 00 69 00 73 00 74 00 20 00 } //01 00 
		$a_03_3 = {6a ff 51 8d 4d cc 33 db 50 51 89 5d e4 89 5d e0 89 5d dc 89 5d cc 89 5d b8 c7 45 bc 08 40 00 00 ff 15 90 01 02 40 00 8d 55 cc 52 68 08 20 00 00 ff 15 90 01 02 40 00 89 45 b8 8d 45 b8 8d 4d dc 50 51 ff 15 90 01 02 40 00 8d 4d cc ff 15 90 01 02 40 00 8b 55 dc 8b 35 90 01 02 40 00 53 52 6a 01 ff d6 50 6a 01 8d 45 e4 6a 11 50 6a 01 68 80 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}