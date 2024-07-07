
rule Trojan_BAT_RedLineStealer_MB_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_03_0 = {02 8e 69 8d 09 00 00 01 13 08 38 90 01 04 fe 90 01 03 45 90 01 08 38 90 01 04 11 08 13 90 02 20 11 07 11 08 16 11 08 8e 69 6f 3b 00 00 0a 26 90 00 } //1
		$a_01_1 = {53 6c 65 65 70 } //1 Sleep
		$a_01_2 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_01_3 = {62 61 73 65 36 34 45 6e 63 6f 64 65 64 44 61 74 61 } //1 base64EncodedData
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //1 FromBase64CharArray
		$a_01_5 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_6 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_7 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}
rule Trojan_BAT_RedLineStealer_MB_MTB_2{
	meta:
		description = "Trojan:BAT/RedLineStealer.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 09 00 00 "
		
	strings :
		$a_80_0 = {47 65 74 54 79 70 65 } //GetType  1
		$a_80_1 = {47 65 74 53 74 72 69 6e 67 } //GetString  1
		$a_80_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //FromBase64String  1
		$a_80_3 = {57 65 62 43 6c 69 65 6e 74 } //WebClient  1
		$a_80_4 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //DownloadFile  1
		$a_80_5 = {4d 44 35 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //MD5CryptoServiceProvider  1
		$a_80_6 = {54 72 69 70 6c 65 44 45 53 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //TripleDESCryptoServiceProvider  1
		$a_80_7 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //CreateDecryptor  1
		$a_00_8 = {d2 f0 a4 9d 82 47 f3 24 19 a6 76 bc 66 ef 7b e2 0a 77 4a cd be 50 ae c8 1c 20 37 2f b2 55 9f 7e ae 97 88 93 e0 a3 31 fa ae 97 88 93 e0 a3 31 fa ae 97 88 93 e0 a3 31 fa ec b5 20 83 24 75 01 67 f4 7e be 23 ad d6 44 53 79 ab 23 e4 b1 5e 02 78 09 e8 94 79 50 e2 49 a4 6e 80 ee 08 a7 51 ec 7f 2a 2d f8 85 d9 23 98 ba 38 b0 4f 51 60 e0 fa 28 c3 a2 53 23 28 4e 93 f3 61 7d 42 20 89 21 2a 77 de fc 23 91 e5 57 f7 ce 5c 1e 47 60 f1 88 5b 3b 16 aa de 0c 5f 38 a9 c1 ad 37 ad 09 4c b7 e8 35 ed 75 06 ed e7 e2 25 52 cf ce e3 0d b6 b4 5b b3 b8 12 91 60 2a 26 c7 e8 f5 0b 84 5d 8d 50 84 ae 3c ce a3 64 } //10
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_00_8  & 1)*10) >=18
 
}