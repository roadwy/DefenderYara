
rule TrojanDownloader_AndroidOS_Hydra_B{
	meta:
		description = "TrojanDownloader:AndroidOS/Hydra.B,SIGNATURE_TYPE_ELFHSTR_EXT,ffffff96 00 64 00 0d 00 00 "
		
	strings :
		$a_00_0 = {c6 44 73 27 63 aa 16 e5 ba 83 6b b2 a9 14 83 c8 f9 b5 2d 16 b1 bc 19 62 63 87 e2 ba 80 94 4a c6 ff 91 f7 32 af 81 9e 08 bd 22 dd a9 c5 fb d5 bb 93 7a ef ba d5 bd d6 a6 b2 6e 1b 7a 3b 63 86 98 b2 d1 47 3e 53 21 59 bd 49 ea 76 1b 3a 09 11 8f 5f 05 03 03 93 56 92 93 e9 13 21 64 37 59 6b e6 20 92 e6 87 0a 77 e4 fe c6 55 2b 09 61 e9 95 89 bd 06 20 20 2a 5c 7d a2 a3 03 27 be bb 4d 47 40 14 a4 10 5e e6 98 6e 0b 64 7a d9 d5 e5 c6 7d } //150
		$a_00_1 = {e7 72 32 b7 00 41 b8 e1 e1 96 41 53 50 19 72 da 4d 60 7f 3c ef 85 37 37 14 75 56 a5 31 e4 72 dc a5 e1 af 41 6c fa 72 81 74 12 23 da 96 c9 1f ef 65 6c 37 10 31 a6 0f 77 db f4 0f 61 56 5b 92 62 3f e0 1c ed ac cc c8 47 0a 96 a1 c3 bc 26 3c c8 1d ab 8b 8e 55 61 7e 3d 02 03 ab 98 6b f7 a5 ea 91 3f aa 75 40 8f c1 bd bf 72 c0 5a dc 48 3b } //150
		$a_00_2 = {86 20 4c e2 e2 02 0f 6f 41 58 5a 88 3f 28 6f 8c 14 fc ed 7c ef 79 94 24 5c ab 25 6d 65 c9 22 b4 02 0d f1 1f 65 05 fe 58 68 5a 05 7d 4a dd ec 91 b3 67 f4 05 d4 73 ad 4a 59 de f3 9d 2d 5b 4a 08 d4 0c 7f a1 9b 85 6b d3 4e 4f aa 2d f7 8d 30 13 e9 7f ee f5 58 56 0c 4e 83 ad f2 f8 48 09 cb 41 12 03 46 56 f8 25 9e 85 5b 0f ad b0 2d 88 54 af } //150
		$a_00_3 = {6c 69 62 68 6f 74 65 72 2e 73 6f } //30 libhoter.so
		$a_00_4 = {6c 69 62 63 6c 65 61 6e 70 6c 61 79 65 72 2e 73 6f } //30 libcleanplayer.so
		$a_00_5 = {6c 69 62 77 69 6c 6c 73 6c 6f 76 65 2e 73 6f } //30 libwillslove.so
		$a_00_6 = {4d 59 44 45 42 55 47 3a 20 46 61 69 6c 65 64 20 74 6f 20 72 65 61 64 20 61 73 73 65 74 20 66 69 6c 65 } //25 MYDEBUG: Failed to read asset file
		$a_00_7 = {4d 59 44 45 42 55 47 3a 20 41 73 73 65 74 20 4c 65 6e 67 74 68 3a 20 25 64 } //25 MYDEBUG: Asset Length: %d
		$a_00_8 = {4d 59 44 45 42 55 47 3a 20 64 65 63 6f 64 65 42 69 74 6d 61 70 20 66 69 6c 65 6e 61 6d 65 20 25 73 } //25 MYDEBUG: decodeBitmap filename %s
		$a_00_9 = {4d 59 44 45 42 55 47 3a 20 67 6f 74 20 66 69 6c 65 6e 61 6d 65 20 25 73 } //25 MYDEBUG: got filename %s
		$a_00_10 = {4d 59 44 45 42 55 47 3a 20 66 69 6c 65 20 6c 65 6e 67 74 68 20 25 64 } //25 MYDEBUG: file length %d
		$a_00_11 = {4d 59 44 45 42 55 47 3a 20 57 69 64 74 68 20 25 64 2c 20 48 65 69 67 68 74 20 25 64 2c 20 53 74 72 69 64 65 20 25 64 } //25 MYDEBUG: Width %d, Height %d, Stride %d
		$a_00_12 = {4d 59 44 45 42 55 47 3a 20 72 65 73 2e 64 61 74 61 28 29 20 25 64 } //25 MYDEBUG: res.data() %d
	condition:
		((#a_00_0  & 1)*150+(#a_00_1  & 1)*150+(#a_00_2  & 1)*150+(#a_00_3  & 1)*30+(#a_00_4  & 1)*30+(#a_00_5  & 1)*30+(#a_00_6  & 1)*25+(#a_00_7  & 1)*25+(#a_00_8  & 1)*25+(#a_00_9  & 1)*25+(#a_00_10  & 1)*25+(#a_00_11  & 1)*25+(#a_00_12  & 1)*25) >=100
 
}