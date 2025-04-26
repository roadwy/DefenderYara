
rule TrojanDownloader_Win32_Hacyayu_A{
	meta:
		description = "TrojanDownloader:Win32/Hacyayu.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {88 1f 0f b6 7d ff 0f b6 db 03 fb 8a 5d fe 81 e7 ff 00 00 00 32 1c 07 fe c1 } //2
		$a_03_1 = {83 7c 24 2c 14 72 16 68 ?? ?? ?? ?? 56 ff 15 } //2
		$a_01_2 = {39 7d f8 74 06 8b 45 f8 31 45 fc } //1
		$a_01_3 = {68 69 64 3d 25 73 26 66 69 6c 65 3d 25 64 } //1 hid=%s&file=%d
		$a_03_4 = {26 73 74 61 74 75 73 3d (67 6f 6f 64|6e 6f 66 69 6c 65) } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=3
 
}