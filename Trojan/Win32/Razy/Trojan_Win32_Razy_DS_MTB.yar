
rule Trojan_Win32_Razy_DS_MTB{
	meta:
		description = "Trojan:Win32/Razy.DS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {b6 d8 2c d8 85 0a 20 32 08 fc ed 9e 39 5c 5c 6c fa 44 8b 8d 22 8d 44 08 8d 45 d8 6a 7e 17 f7 0d 1c 1b f6 62 27 8b 48 a8 00 02 81 4d 42 cd f0 db cc b0 26 a0 da bf df 6c 86 01 7b 23 d9 e0 41 1d 41 e8 df 18 3b 70 ac } //1
		$a_01_1 = {16 37 40 48 e5 83 f0 e8 0b 84 c9 dc b7 a9 88 01 eb d0 56 93 08 be e7 b6 ee 5c 39 25 11 83 fa 1e 21 4d 71 98 e3 98 7b 83 f9 09 74 3e 3b f8 0d 31 20 dd ba 93 3d 0a 75 0b 6e eb c9 15 3b 56 74 2c 76 42 7b ce 67 9d 9b 10 } //1
		$a_01_2 = {ca 08 a5 3e 3d 83 a5 dd c9 76 0c 01 c8 fc e8 f3 ed 1a ee 63 c7 85 f8 b4 f0 09 68 fc 72 50 7b dd 77 37 4b 85 f4 14 6a 01 68 bb e3 61 b5 21 05 dd 18 77 5f 12 68 38 80 e8 73 96 14 1f ba 96 e4 c0 be e4 81 fc 1c 56 3c 2c 84 7d 53 02 1f 36 3c 1c ec 1e 19 } //1
		$a_01_3 = {ea f7 16 9f 1b f8 ee 28 f6 e8 8d 2c d4 29 68 70 26 c3 16 9b 8d cd e7 1b 2d 48 77 10 b6 d8 63 32 22 d8 5e 4d 14 ac 74 8a 9d 31 20 fc 7b 20 9f 63 93 ef 94 49 79 17 e3 15 ff 35 66 91 b3 03 76 11 d1 9f 9b 7c 67 bf b5 } //1
		$a_01_4 = {db 68 c0 b0 67 b7 3b c9 68 af ef 04 e8 a6 50 b0 ee 10 08 16 ee e4 8f ff 3c 08 47 21 f2 95 6a b7 01 7e d6 ec ec 58 ec 68 a4 7f 1d e8 5e 7f 00 01 b6 d8 2c d8 85 0a 20 32 08 fc ed 9e 39 5c 5c 6c fa 44 8b 8d 22 8d } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}