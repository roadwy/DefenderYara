
rule TrojanDownloader_Win32_Banload_ACZ{
	meta:
		description = "TrojanDownloader:Win32/Banload.ACZ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {64 ff 32 64 89 22 3d d9 1e 00 00 74 90 01 01 8d 45 fc b9 90 01 04 8b 15 90 01 04 e8 90 01 04 8b 55 fc 90 00 } //01 00 
		$a_02_1 = {68 74 74 70 3a 2f 2f 90 02 20 2e 62 72 2f 90 02 20 2e 90 03 03 03 65 78 65 6a 70 67 90 00 } //01 00 
		$a_02_2 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 90 02 20 63 3a 5c 61 72 71 75 69 76 6f 20 64 65 20 70 72 6f 67 72 61 6d 61 73 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}