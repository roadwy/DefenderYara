
rule TrojanDownloader_Win32_Wunkay_A{
	meta:
		description = "TrojanDownloader:Win32/Wunkay.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {b9 54 00 00 00 2b e1 8b fc 33 c0 f3 aa } //1
		$a_02_1 = {85 c0 74 0c 68 (40 77 1b|e0 8c 1a) 00 e8 ?? 00 00 00 eb ?? 8d 85 ?? f9 ff ff 8d 95 ?? fb ff ff 6a 00 6a 00 50 52 6a 00 } //1
		$a_02_2 = {8d 43 f0 50 8d 43 ac 50 (33 d2 52 52 52 52 52 52 52|33 c0 b9 07 00 00 00 50 e2 fd) } //1
		$a_00_3 = {8d 95 d8 f9 ff ff 8d 43 f0 50 8d 43 ac 50 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 52 e8 dc 00 00 00 85 c0 74 0c 68 40 77 1b 00 e8 ec 00 00 00 } //1
		$a_00_4 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_02_5 = {00 07 47 e2 fb 68 ?? ?? 00 10 64 ff 35 00 00 00 00 64 89 25 00 00 00 00 e8 ?? 00 00 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_02_5  & 1)*1) >=5
 
}