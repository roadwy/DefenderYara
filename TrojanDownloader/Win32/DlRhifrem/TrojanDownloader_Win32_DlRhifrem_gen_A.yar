
rule TrojanDownloader_Win32_DlRhifrem_gen_A{
	meta:
		description = "TrojanDownloader:Win32/DlRhifrem.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {3d c8 00 00 00 0f 85 ?? ?? 00 00 c7 44 24 18 00 00 00 00 c7 44 24 14 80 00 00 00 c7 44 24 10 02 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 08 02 00 00 00 c7 44 24 04 00 00 00 40 [0-06] 89 04 24 e8 } //2
		$a_03_1 = {7d 3b 8b 45 ?? 03 45 e8 fe 08 8b 45 ec 8b 4d e8 01 c1 8b 45 08 8b 5d e8 01 c3 8b 55 e8 8d 45 f0 89 45 e4 89 d0 8b 75 e4 99 f7 3e 8b 45 0c 0f b6 04 10 32 03 88 01 8d 45 e8 ff 00 eb bd } //1
		$a_03_2 = {c7 44 24 14 00 00 00 00 c7 44 24 10 00 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 ?? ?? ?? 0c 61 c7 44 24 04 00 00 00 00 c7 04 24 00 00 00 00 e8 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}