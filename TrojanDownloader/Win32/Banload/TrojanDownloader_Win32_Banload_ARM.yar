
rule TrojanDownloader_Win32_Banload_ARM{
	meta:
		description = "TrojanDownloader:Win32/Banload.ARM,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 75 70 6c 6f 61 64 73 2e 62 6f 78 69 66 79 2e 6d 65 2f } //1 http://uploads.boxify.me/
		$a_00_1 = {eb 52 80 7d e7 00 74 4c 8b 45 fc 80 b8 8b 00 00 00 02 75 40 8b 45 fc 66 81 b8 38 01 00 00 fc 00 73 0f 8d 45 e8 ba } //1
		$a_03_2 = {8b 45 f4 05 a0 00 00 00 8b 55 fc e8 ?? ?? ?? ff 8b 45 f4 05 b0 00 00 00 8b 55 f8 e8 ?? ?? ?? ff 33 d2 8b 45 f4 8b 08 ff 51 40 33 c0 5a 59 59 } //1
		$a_03_3 = {80 7d ff 00 75 7e b8 1a 00 00 00 e8 ?? ?? ?? ff 8b 14 85 ?? ?? ?? ?? 8d 45 f8 e8 ?? ?? ?? ff 80 7d fe 00 74 40 b8 02 00 00 00 e8 ?? ?? ?? ff 2c 01 72 04 74 19 eb 43 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}