
rule TrojanDownloader_Win32_Banload_AJK{
	meta:
		description = "TrojanDownloader:Win32/Banload.AJK,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {b8 1c 00 00 00 e8 ?? ?? fe ff ba ?? ?? 41 00 8a 14 02 8d 45 f8 e8 ?? ?? fe ff 8b 55 f8 8d 45 fc e8 ?? ?? fe ff 4b 75 d8 } //1
		$a_01_1 = {7a 61 79 62 78 6a 6b 71 72 63 6c 6d 77 6e 6f 70 64 74 75 73 74 65 66 67 68 69 75 76 } //1 zaybxjkqrclmwnopdtustefghiuv
		$a_01_2 = {68 6f 73 70 2d 61 74 74 30 36 2e 6e 6d 2e 72 75 } //1 hosp-att06.nm.ru
		$a_01_3 = {07 00 00 00 5c 46 6f 6e 74 73 5c 00 ff ff ff ff 04 00 00 00 2e 65 78 65 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}