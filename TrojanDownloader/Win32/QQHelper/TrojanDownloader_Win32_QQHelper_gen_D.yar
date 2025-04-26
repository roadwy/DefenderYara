
rule TrojanDownloader_Win32_QQHelper_gen_D{
	meta:
		description = "TrojanDownloader:Win32/QQHelper.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 20 a1 ?? ?? ?? 10 8b 0d ?? ?? ?? 10 33 c4 53 55 56 33 db 83 f9 04 89 44 24 28 57 75 08 33 c9 89 0d ?? ?? ?? 10 8b 7c 24 40 33 f6 8a 04 3e 3c 61 7c 1e 3c 7a 7f 1a 8b e9 69 ed 01 04 00 00 0f be d0 8a 92 ?? ?? ?? 10 88 94 2e ?? ?? ?? 10 eb 31 3c 41 7c 1e 3c 5a 7f 1a 8b e9 69 ed 01 04 00 00 0f be d0 8a 92 ?? ?? ?? 10 88 94 2e ?? ?? ?? 10 eb 0f 8b d1 69 d2 01 04 00 00 88 84 32 ?? ?? ?? 10 3a c3 74 09 46 81 fe 00 04 00 00 7c 9d c7 44 24 28 0f 00 00 00 89 5c 24 24 88 5c 24 14 6a ?? 68 ?? ?? ?? 10 8d 4c 24 18 89 5c 24 40 e8 ?? ?? ?? ff 8b 0d ?? ?? ?? 10 8b c1 69 c0 01 04 00 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}