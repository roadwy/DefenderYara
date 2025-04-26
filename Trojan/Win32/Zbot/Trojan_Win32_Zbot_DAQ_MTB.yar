
rule Trojan_Win32_Zbot_DAQ_MTB{
	meta:
		description = "Trojan:Win32/Zbot.DAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {76 31 23 5c c0 86 14 a0 fc 91 58 84 1e 62 02 82 84 08 3d 3f cb ac 70 c3 75 d2 3e b6 dc 74 1a 26 94 6b f1 6d 77 0e 63 3d 6a 33 2c 6d 25 ca f6 77 db 5b a1 ec 74 2e f8 e1 df c8 d9 5b df 8c e3 f1 5a 53 ba 51 2c 03 e5 c4 80 52 40 c1 4e 52 9f } //1
		$a_01_1 = {8b 0c 4f 35 f5 6a 9a c8 1f 74 a1 9c 47 13 ed 89 fa 12 be 75 ec dc c6 c2 da b0 92 74 6e dc 92 4b 57 7b b1 79 54 b1 e3 bb cd ba 8f f1 d1 18 62 b4 4a 6b b3 c5 1e 7a c9 a9 d4 a5 bc f5 24 78 52 e4 64 51 a6 7a 7e 66 49 2f 69 4b 55 eb 87 da 0e 4e } //1
		$a_01_2 = {7d de f3 71 d7 d8 a9 58 1f 8e 03 f5 da 50 5a 58 ec 02 45 ae 17 52 9a b4 62 32 35 41 bf 78 9c 07 e1 93 bb ed b6 ee 62 37 cc 33 25 6c d7 9b 83 33 2a 3d 08 bd 40 91 3c 2e 72 6e a3 50 5c f4 35 cb 07 56 94 e4 6e 72 38 51 b5 d8 93 } //1
		$a_01_3 = {6c 12 35 71 b6 18 92 17 ed a3 0f 29 13 9a a5 c8 23 27 bb 78 92 a5 ff 08 9d 57 ce 77 de e6 47 b3 79 4d 4d e2 68 d4 3e 41 aa d4 26 11 cb 4a 56 11 49 ce b1 e0 db 18 a5 61 } //1
		$a_01_4 = {ed 96 bf 16 26 2b 2f fe 1d 33 5f fd 6d 07 90 47 4f 94 3a 4d 45 98 92 4b dd 08 2e 93 76 39 2b 48 4c 81 51 cd f6 6d ff fc 66 a2 03 5c 80 c0 74 96 9f 91 e3 04 16 32 2a e9 c0 38 03 9e 42 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}