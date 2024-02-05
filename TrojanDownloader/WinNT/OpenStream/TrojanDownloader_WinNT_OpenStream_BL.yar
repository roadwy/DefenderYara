
rule TrojanDownloader_WinNT_OpenStream_BL{
	meta:
		description = "TrojanDownloader:WinNT/OpenStream.BL,SIGNATURE_TYPE_JAVAHSTR_EXT,15 00 15 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {01 00 20 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 90 01 01 71 72 73 74 75 76 77 78 79 7a 3a 2f 2e 3d 26 2d 90 00 } //0a 00 
		$a_00_1 = {06 5b 5e 30 2d 39 5d } //01 00 
		$a_03_2 = {01 00 10 30 90 01 01 31 35 90 01 08 31 39 90 01 01 30 90 00 } //01 00 
		$a_03_3 = {01 00 12 34 90 01 01 32 31 90 01 09 38 31 90 01 01 34 31 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}