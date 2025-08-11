
rule TrojanDownloader_Win64_Tedy_NITA_MTB{
	meta:
		description = "TrojanDownloader:Win64/Tedy.NITA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 d2 ff 15 70 e5 1d 00 48 8b f8 48 85 c0 74 14 8b d5 48 8b c8 ff 15 8d e5 1d 00 48 8b cf ff 15 24 e5 1d 00 48 83 7b 18 07 4c 8b c3 76 03 4c 8b 03 48 8d 15 78 7b 23 00 48 8d 8c 24 f0 02 00 00 e8 b3 f0 ff ff 48 8d 84 24 f0 02 00 00 c7 44 24 30 70 00 00 00 48 8d 4c 24 30 48 89 44 24 50 c7 44 24 34 40 00 00 00 4c 89 74 24 38 4c 89 7c 24 40 4c 89 64 24 48 4c 89 74 24 58 44 89 74 24 60 ff 15 0a e6 1d 00 85 c0 } //2
		$a_01_1 = {4c 8d 3d 3f 7c 23 00 4c 8d 25 78 7c 23 00 33 d2 b9 02 00 00 00 41 8b f6 ff 15 f8 e5 1d 00 48 8b f8 48 83 f8 ff 0f 84 47 01 00 00 48 8d 94 24 b0 00 00 00 c7 84 24 b0 00 00 00 38 02 00 00 48 8b c8 ff 15 af e5 1d 00 85 c0 0f 84 1a 01 00 00 48 83 7b 18 07 48 8b d3 76 03 48 8b 13 48 8d 8c 24 dc 00 00 00 e8 55 ab 1a 00 85 c0 74 17 48 8d 94 24 b0 00 00 00 48 8b cf ff 15 80 e5 1d 00 85 c0 75 cd } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}