
rule TrojanDownloader_Win32_Cbeplay_B{
	meta:
		description = "TrojanDownloader:Win32/Cbeplay.B,SIGNATURE_TYPE_PEHSTR_EXT,38 00 38 00 06 00 00 28 00 "
		
	strings :
		$a_02_0 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 53 79 73 74 65 6d 33 32 5c 43 90 02 03 45 76 74 53 76 63 2e 65 78 65 20 2d 6b 20 6e 65 74 73 76 63 73 90 00 } //05 00 
		$a_80_1 = {26 76 65 72 3d 25 73 26 69 64 78 3d 25 73 26 75 73 65 72 3d 25 73 } //&ver=%s&idx=%s&user=%s  05 00 
		$a_80_2 = {25 73 26 69 6f 63 74 6c 3d 25 64 26 64 61 74 61 3d 25 73 } //%s&ioctl=%d&data=%s  03 00 
		$a_00_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //03 00  URLDownloadToFileA
		$a_00_4 = {53 74 61 72 74 53 65 72 76 69 63 65 41 } //03 00  StartServiceA
		$a_01_5 = {47 65 74 43 75 72 72 65 6e 74 48 77 50 72 6f 66 69 6c 65 57 } //00 00  GetCurrentHwProfileW
	condition:
		any of ($a_*)
 
}