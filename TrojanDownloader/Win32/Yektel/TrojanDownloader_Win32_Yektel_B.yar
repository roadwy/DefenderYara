
rule TrojanDownloader_Win32_Yektel_B{
	meta:
		description = "TrojanDownloader:Win32/Yektel.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {47 66 81 ff 28 23 7d 52 33 c0 89 04 24 54 6a 00 55 e8 ?? ?? ?? ff e8 ?? ?? ?? ff } //1
		$a_03_1 = {66 ff 45 ee 66 81 7d ee 28 23 7d 69 33 c0 89 45 f4 8d 45 f4 50 6a 00 8b 45 f8 50 e8 ?? ?? ff ff e8 ?? ?? ff ff } //1
		$a_03_2 = {19 04 74 0b 66 81 3d ?? ?? ?? ?? 22 04 75 1f a1 ?? ?? ?? ?? 8b 00 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*2) >=3
 
}