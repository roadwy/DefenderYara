
rule TrojanDownloader_MacOS_AmdDwn_B_MTB{
	meta:
		description = "TrojanDownloader:MacOS/AmdDwn.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {00 00 62 1e e8 67 6a b2 e8 3b e8 f2 01 01 67 9e 00 18 61 1e 08 00 d8 d2 08 0b e8 f2 01 01 67 9e 02 10 6e 1e 00 08 41 1f 13 ?? ?? ?? 00 00 80 52 fd 7b 45 a9 f4 4f 44 a9 f6 57 43 a9 ff 83 01 91 } //2
		$a_03_1 = {e8 bf c0 39 e9 0f 40 f9 1f 01 00 71 28 b1 94 9a e8 7f 00 a9 e0 03 13 aa e1 03 13 aa 56 ?? ?? ?? e8 bf c0 39 e8 00 f8 37 20 00 80 52 fd 7b 45 a9 f4 4f 44 a9 f6 57 43 a9 ff 83 01 91 } //1
		$a_03_2 = {e8 01 80 52 e8 1b 00 b9 e8 1b 40 b9 1f 4d 00 71 48 ?? ?? ?? 09 00 00 ?? 29 71 36 91 ca fc ff 10 2b 69 68 38 4a 09 0b 8b 40 01 1f d6 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}