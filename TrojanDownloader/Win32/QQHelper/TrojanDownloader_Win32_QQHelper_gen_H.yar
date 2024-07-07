
rule TrojanDownloader_Win32_QQHelper_gen_H{
	meta:
		description = "TrojanDownloader:Win32/QQHelper.gen!H,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 20 a1 90 01 03 10 8b 0d 90 01 03 10 33 c4 53 56 33 db 83 f9 04 89 44 24 24 57 75 08 33 c9 89 0d 90 01 03 10 8b 54 24 3c 33 f6 8a 04 16 3c 61 7c 0f 3c 7a 7f 0b 0f be c0 8a 80 90 01 03 10 eb 11 3c 41 7c 0d 3c 5a 7f 09 0f be c0 8a 80 90 01 03 10 8b f9 69 ff 01 04 00 00 88 84 37 90 01 03 10 38 1c 16 74 09 46 81 fe 00 04 00 00 7c bc c7 44 24 24 90 01 01 00 00 00 89 5c 24 20 88 5c 24 10 6a 90 01 01 68 90 01 03 10 8d 4c 24 14 89 5c 24 3c e8 90 01 04 8b 0d 90 01 03 10 8b c1 69 c0 01 04 00 00 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}