
rule TrojanDownloader_Win32_Banload_BFH{
	meta:
		description = "TrojanDownloader:Win32/Banload.BFH,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {61 70 70 64 61 74 61 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2a 00 2e 00 2a 00 } //1
		$a_01_1 = {89 45 f8 83 7d f8 00 75 0a 33 c0 89 45 fc e9 58 01 00 00 33 c0 55 68 } //1
		$a_01_2 = {7d 03 47 eb 05 bf 01 00 00 00 8b 45 e8 33 db 8a 5c 38 ff 33 5d e4 3b 5d f0 7f 0b 81 c3 ff 00 00 00 2b 5d f0 eb 03 } //1
		$a_03_3 = {ff ff 84 c0 0f 84 ?? ?? 00 00 8d 55 fc b8 ?? ?? ?? 00 e8 ?? ?? ?? ff 8d 45 fc ba ?? ?? ?? 00 e8 ?? ?? ?? ff 8b 55 fc 8b 83 fc 02 00 00 e8 ?? ?? ?? ff 8d 55 f8 8b 83 fc 02 00 00 e8 ?? ?? ?? ff 8d 45 f8 50 8d 55 f0 8b 83 ?? 03 00 00 e8 ?? ?? ?? ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}