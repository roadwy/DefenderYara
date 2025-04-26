
rule Ransom_MacOS_EvilQuest_C_MTB{
	meta:
		description = "Ransom:MacOS/EvilQuest.C!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {58 59 33 34 35 4e 35 73 23 70 24 28 3c 64 36 48 6a 61 4b 76 74 21 44 4c 2b 4d 61 69 79 5d 2d 30 3b 61 6d 50 35 42 65 } //1 XY345N5s#p$(<d6HjaKvt!DL+Maiy]-0;amP5Be
		$a_02_1 = {c0 89 c6 48 8b bd 30 ff ff ff ba 02 00 00 00 e8 [0-04] 48 8b bd 30 ff ff ff 89 85 e4 fe ff ff e8 [0-04] 31 c9 89 ce 31 d2 48 89 45 d0 48 8b bd 30 ff ff ff e8 [0-04] 48 83 7d d0 00 0f 87 [0-04] 48 8b bd 30 ff ff ff e8 [0-04] 48 8b bd 30 ff ff ff e8 [0-04] c7 45 fc fd ff ff ff e9 } //1
		$a_00_2 = {48 89 e5 48 83 ec 10 48 89 7d f8 bf 05 00 00 00 48 8d 35 c8 ff ff ff e8 7f 67 01 00 cc 83 3d 27 c0 01 00 00 0f 85 1b 00 00 00 48 8d 3d be 78 01 00 31 c0 e8 0f 67 01 00 bf 33 00 00 00 89 45 f4 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=2
 
}