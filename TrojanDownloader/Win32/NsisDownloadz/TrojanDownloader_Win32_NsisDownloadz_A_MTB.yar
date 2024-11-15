
rule TrojanDownloader_Win32_NsisDownloadz_A_MTB{
	meta:
		description = "TrojanDownloader:Win32/NsisDownloadz.A!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {36 74 57 90 6f c8 bb b2 60 bb d8 4e 30 5f bf ea 81 70 2b a3 08 c4 b7 88 d8 14 04 d4 f2 ec 50 d6 ef 9f 6a 8f 46 82 f3 ab 8e 89 d1 1b 7d 7b 5d ff 9a d5 95 f1 47 4f 1b 25 ae 37 77 33 a4 a6 11 c5 41 3e 91 d0 3d bc a7 27 79 f9 85 bf 01 ee b4 19 cd 6f de 97 0a a6 7b bd e9 d7 29 9b 24 4c e7 ba e1 8d 21 6c b5 14 f5 c8 06 9e f8 ca 80 } //1
		$a_01_1 = {60 28 c1 3b 8c ea a9 c4 3c 25 24 c8 ec fd 42 1e 7c cd 28 c1 64 50 59 b0 54 07 d4 7b 99 fe a5 8c 00 fd c7 93 be aa 4d 7d 12 04 33 ec aa d2 fb 6c 03 4f 75 0e 97 95 a0 ec e7 0d 8d fb 75 24 dd 93 7e 8a 73 b5 8a 61 5a 42 83 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}