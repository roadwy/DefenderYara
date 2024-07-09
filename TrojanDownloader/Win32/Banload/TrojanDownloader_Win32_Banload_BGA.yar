
rule TrojanDownloader_Win32_Banload_BGA{
	meta:
		description = "TrojanDownloader:Win32/Banload.BGA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {33 d2 b8 1a 00 00 00 e8 b3 fb ff ff 6a 00 8d 45 c8 50 8d 85 10 ff ff ff 33 d2 e8 ?? ?? f7 ff 8d 8d 10 ff ff ff 33 d2 b8 ?? ?? ?? 00 e8 ?? ?? ff ff 8d 85 0c ff ff ff e8 ?? ?? ff ff 8b 95 0c ff ff ff 8d 45 c4 b9 ?? ?? ?? 00 } //1
		$a_03_1 = {e9 25 01 00 00 8d 45 f4 ba ?? ?? ?? 00 e8 ?? ?? ?? ff 8d 45 f8 33 d2 e8 ?? ?? ?? ff 8b 45 f4 85 c0 74 16 8b d0 83 ea 0a 66 83 3a 02 74 0b } //1
		$a_03_2 = {8d 4d d8 33 d2 b8 ?? ?? ?? 00 e8 ?? ?? ff ff 6a 00 8d 45 f0 50 8d 45 c8 33 d2 e8 ?? ?? ?? ff 8d 4d c8 33 d2 b8 ?? ?? ?? 00 e8 ?? ?? ff ff 8d 4d ec 33 d2 b8 1a 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}