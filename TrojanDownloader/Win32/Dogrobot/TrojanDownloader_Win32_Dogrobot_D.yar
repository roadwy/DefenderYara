
rule TrojanDownloader_Win32_Dogrobot_D{
	meta:
		description = "TrojanDownloader:Win32/Dogrobot.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {65 c6 45 f6 74 c6 45 f7 63 c6 45 f8 5c c6 45 f9 68 c6 45 fa 6f c6 45 fb 73 c6 45 fc 74 c6 45 fd 73 } //1
		$a_03_1 = {73 66 a5 c6 45 ?? 63 c6 45 ?? 76 c6 45 ?? 68 c6 45 ?? 6f c6 45 ?? 73 c6 45 ?? 74 c6 45 ?? 2e c6 45 ?? 65 c6 45 ?? 78 c6 45 ?? 65 } //1
		$a_01_2 = {8b 4d 0c 31 06 46 e2 fb 57 } //1
		$a_01_3 = {58 45 54 54 45 54 54 2e 2e 2e 2e 2e 2e 00 } //1 䕘呔呅⹔⸮⸮.
		$a_03_4 = {26 64 74 69 6d 65 3d [0-05] 26 6f 73 3d [0-05] 26 76 65 72 3d [0-05] 3f 6d 61 63 3d } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=3
 
}