
rule TrojanDownloader_Win32_Dogrobot_D{
	meta:
		description = "TrojanDownloader:Win32/Dogrobot.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 c6 45 f6 74 c6 45 f7 63 c6 45 f8 5c c6 45 f9 68 c6 45 fa 6f c6 45 fb 73 c6 45 fc 74 c6 45 fd 73 } //01 00 
		$a_03_1 = {73 66 a5 c6 45 90 01 01 63 c6 45 90 01 01 76 c6 45 90 01 01 68 c6 45 90 01 01 6f c6 45 90 01 01 73 c6 45 90 01 01 74 c6 45 90 01 01 2e c6 45 90 01 01 65 c6 45 90 01 01 78 c6 45 90 01 01 65 90 00 } //01 00 
		$a_01_2 = {8b 4d 0c 31 06 46 e2 fb 57 } //01 00 
		$a_01_3 = {58 45 54 54 45 54 54 2e 2e 2e 2e 2e 2e 00 } //01 00 
		$a_03_4 = {26 64 74 69 6d 65 3d 90 02 05 26 6f 73 3d 90 02 05 26 76 65 72 3d 90 02 05 3f 6d 61 63 3d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}