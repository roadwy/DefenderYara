
rule TrojanDownloader_Win32_PterodoGen_B_dha{
	meta:
		description = "TrojanDownloader:Win32/PterodoGen.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_43_0 = {52 04 88 90 01 0b 74 21 b8 cd cc cc cc f7 90 01 01 8b 90 01 01 c1 ea 03 8d 0c 92 03 c9 2b c1 8a 80 90 01 04 30 04 90 01 02 3b 90 01 01 72 df 90 00 01 } //1
		$a_8d_1 = {04 88 90 01 0d 74 21 b8 cd cc cc cc f7 90 01 01 8b 90 01 01 c1 ea 03 8d 0c 92 03 c9 2b c1 8a 80 90 01 04 30 04 90 01 02 3b 90 01 01 72 df 90 00 01 00 32 43 2b fe be 00 00 00 00 74 21 b8 cd cc cc cc f7 } //12800
		$a_8b_2 = {01 } //400
		$a_03_3 = {8d 0c 92 03 c9 2b c1 8a 80 90 01 04 30 04 90 01 02 3b 90 01 01 72 df 90 00 01 00 45 41 c7 45 f8 00 00 00 00 c7 45 fc 00 00 00 00 eb 09 8b 45 fc 83 c0 01 89 45 fc 8b 4d fc 3b 4d 0c 73 24 8b 55 08 03 55 fc 0f b6 0a 8b 45 fc 33 d2 f7 75 14 8b 45 10 0f b6 14 10 33 ca 8b 45 08 03 45 fc 88 08 eb cb 00 00 5d 04 00 00 44 00 05 80 5c 28 00 00 45 00 05 80 00 00 01 00 04 00 12 00 88 21 50 74 65 72 6f 64 6f 47 65 6e 2e 43 21 64 68 61 00 00 01 40 05 82 5c 00 04 00 78 6a 00 00 01 00 01 00 02 00 00 01 00 31 41 0f b7 45 fc 8b 4d 08 0f be 0c 01 0f b7 45 fc 0f b7 55 18 03 c2 0f b7 75 14 99 f7 fe 8b 45 10 0f be 14 10 33 ca 0f b7 45 fc 8b 55 f8 88 0c 02 eb ba 01 00 28 41 8b 04 24 89 d1 31 d2 01 d8 f7 f6 8b 44 24 } //49409
	condition:
		((#a_43_0  & 1)*1+(#a_8d_1  & 1)*12800+(#a_8b_2  & 1)*400+(#a_03_3  & 1)*49409) >=1
 
}