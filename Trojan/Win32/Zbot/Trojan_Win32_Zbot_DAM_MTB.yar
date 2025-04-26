
rule Trojan_Win32_Zbot_DAM_MTB{
	meta:
		description = "Trojan:Win32/Zbot.DAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {45 fa a2 99 d2 37 9c 55 eb 69 a8 d2 cc 4f 92 09 38 81 da 3a ec e9 bc e9 06 f9 21 93 dc 09 9d 81 fd 60 56 59 6d 6a ba 6f d6 e0 51 1f 75 91 f1 4a } //1
		$a_01_1 = {41 fe 45 e7 a9 ea 33 a9 a9 da 02 f9 aa 1b 60 82 7d 70 ac ad ae af 0b 99 6c 92 2f 97 64 de 12 74 58 ce 1a 47 ad 1f f3 c4 01 a8 56 ba 4c 49 e3 bb d1 dd b8 59 5c fc ac } //1
		$a_01_2 = {f8 ea 81 c2 10 8b 0a a5 90 00 29 0f ba c9 f3 4b 7f 6d 68 e9 7e 19 09 01 11 13 bd 53 03 c2 7c 50 df 31 57 a6 e8 79 12 44 f7 80 0d 01 ea 21 d7 15 15 b8 55 40 d3 c8 01 4e d4 c3 } //1
		$a_01_3 = {1d 36 2e a4 66 2c 44 02 03 9c 1f ff 34 24 e9 84 50 08 11 06 4b 8e fb 33 03 b6 83 f8 02 c1 0e 87 30 19 98 0e 17 76 dd 18 1e bb 1a 0a ea 0c 82 40 4b 1b 01 ab 9e 14 } //1
		$a_01_4 = {7d 5e b2 e4 9e f0 f9 44 00 57 03 86 09 2d b6 60 31 01 72 f2 62 73 22 e9 46 3e f2 53 b5 eb 8e 1e 5c 91 80 58 68 d1 47 12 5f 33 e2 49 b4 ae 38 3c 6d c1 25 8d b5 3e 45 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}