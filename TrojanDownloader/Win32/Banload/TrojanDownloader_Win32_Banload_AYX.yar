
rule TrojanDownloader_Win32_Banload_AYX{
	meta:
		description = "TrojanDownloader:Win32/Banload.AYX,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {b8 68 58 4d 56 bb 12 f7 6c 3c b9 0a 00 00 00 66 ba 58 56 ed b8 01 00 00 00 eb 13 } //1
		$a_03_1 = {33 d2 b8 07 00 00 00 e8 ?? ?? ff ff 8b 55 f0 b8 ?? ?? ?? ?? b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 4d ec 33 d2 b8 07 00 00 00 e8 ?? ?? ff ff 8b 55 ec b8 ?? ?? ?? ?? e8 } //1
		$a_03_2 = {84 c0 75 29 8b 45 f8 83 c0 60 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 f8 83 c0 64 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}