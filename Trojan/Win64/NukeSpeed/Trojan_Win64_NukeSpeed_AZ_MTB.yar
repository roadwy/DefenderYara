
rule Trojan_Win64_NukeSpeed_AZ_MTB{
	meta:
		description = "Trojan:Win64/NukeSpeed.AZ!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6e 5f 3e f0 e4 75 40 95 7b 13 f3 aa 83 8c dc bd ae b4 dc 67 8f 64 c0 f4 e4 8f 5c 04 a7 f0 b7 6f f3 e0 8a 69 4c f8 ca a4 88 49 14 e9 94 d2 45 95 40 49 14 be 9a 55 e2 c7 0d 33 3d 83 26 4b 31 72 } //1
		$a_01_1 = {20 f7 39 37 0a f7 29 97 22 30 4d 8a f7 f5 e0 ea 47 45 68 f5 bf 90 02 55 4a a4 62 95 dd 71 b2 a3 35 69 47 9e 41 b7 92 76 78 77 04 a8 ff 16 96 fa ba 49 fe 72 1e 78 fd 5e 32 3f 5e ae a5 db c2 cd } //1
		$a_01_2 = {71 5f 4c 1f 1b cd 49 ae 93 2f 31 dd 67 5d a7 a3 c3 95 fc 58 0b 4e e6 ba 77 ec d3 4f 1d 99 bc 5d 49 09 d4 a1 b2 9c 69 64 f4 2b 0a ba 4e ba 48 96 d3 10 c9 da b5 3e 50 3d 6f 98 14 a7 45 c6 54 1c 24 32 e6 bd 70 4e d8 71 74 6f 29 0e bb b3 b1 84 3e 78 26 } //1
		$a_01_3 = {ba 83 68 95 66 4e c9 f0 7b a9 b9 c1 b3 a3 08 9a 0d 69 6f 99 95 bc 69 9d 33 96 df 3f 62 6f 34 3b 65 11 ff 6c 0c 9d a8 2c 42 ff 37 26 31 cc 65 51 a1 c5 98 49 78 99 b5 73 df 7c bd 6a 3e 1c eb b0 c1 9e e6 59 d7 52 dc 3c 34 2d d6 c3 65 d5 a2 c3 c1 14 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}