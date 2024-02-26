
rule TrojanDownloader_Win32_ScarletFlash_A{
	meta:
		description = "TrojanDownloader:Win32/ScarletFlash.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_43_0 = {b6 04 1e 88 04 3e 88 0c 1e 0f b6 04 3e 8b 4d fc 03 c2 8b 55 f4 0f b6 c0 0f b6 04 90 01 01 30 04 11 41 89 4d fc 3b 4d f8 72 90 00 01 } //00 20 
		$a_8b_1 = {f0 8b 4d e0 8b 55 e8 0f b6 00 03 45 f8 0f b6 c0 8a 04 03 30 04 0f 47 8b 45 f4 3b 7d ec 0f 02 00 0c 01 34 56 c4 fc 4b c2 12 9a 50 34 8a bc 00 00 5d 04 00 00 3f a3 03 80 5c 26 00 00 40 a3 03 80 00 } //00 01 
	condition:
		any of ($a_*)
 
}