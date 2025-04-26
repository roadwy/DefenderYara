
rule Ransom_MacOS_Filecoder_YA_MTB{
	meta:
		description = "Ransom:MacOS/Filecoder.YA!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_00_0 = {48 89 e5 48 83 ec 20 48 89 7d f8 c7 45 f4 00 00 00 00 48 8b 7d f8 48 c7 c6 fc ff ff ff ba 02 00 00 00 e8 7e 14 00 00 48 8d 75 f4 48 8b 4d f8 48 89 f7 be 01 00 00 00 ba 04 00 00 00 89 45 f0 e8 55 14 00 00 45 31 c0 44 89 c6 31 d2 48 8b 7d f8 48 89 45 e8 e8 4c 14 00 00 81 7d f4 be ba be dd 41 0f 94 c1 41 80 e1 01 41 0f b6 d1 89 45 e4 89 d0 48 83 c4 20 5d c3 } //1
		$a_00_1 = {48 8b 7d c0 48 8b 45 c0 48 89 bd 78 ff ff ff 48 89 c7 e8 78 f9 00 00 48 8b 4d b8 48 8b bd 78 ff ff ff be 01 00 00 00 48 89 c2 e8 94 f8 00 00 48 89 45 b0 48 8b 7d b8 e8 81 f8 00 00 48 8b 7d b8 e8 48 f8 00 00 48 8b 7d c0 89 85 74 ff ff ff e8 51 f8 00 00 48 8b 4d b0 48 8b 7d c0 48 89 8d 68 ff ff ff e8 27 f9 00 00 } //1
		$a_01_2 = {74 6f 69 64 69 65 76 69 74 63 65 66 66 65 2f 6c 69 62 70 65 72 73 69 73 74 2f 72 65 6e 6e 75 72 2e 63 } //1 toidievitceffe/libpersist/rennur.c
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}