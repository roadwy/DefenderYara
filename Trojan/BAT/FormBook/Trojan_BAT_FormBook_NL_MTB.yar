
rule Trojan_BAT_FormBook_NL_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {13 04 11 04 2c 0d 00 72 90 01 04 28 90 01 03 0a 26 00 06 04 58 0d 08 09 59 04 5d 0b 02 03 7e 90 01 03 04 5d 07 28 90 01 03 06 9c 02 13 05 2b 00 11 05 2a 90 00 } //01 00 
		$a_03_1 = {02 03 17 58 90 01 05 5d 91 0a 16 0b 02 03 28 90 00 } //01 00 
		$a_03_2 = {20 16 f8 00 00 0c 2b 13 00 06 08 20 00 01 00 00 28 90 01 04 0a 00 08 15 58 0c 08 16 fe 04 16 fe 01 0d 09 2d e2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_FormBook_NL_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {1f 10 28 e5 00 00 06 9c 11 05 20 05 60 ec 78 5a 20 9d 8b cb 32 61 38 50 ff ff ff 11 05 20 30 f3 e6 9a 5a 20 86 d2 1d 9c 61 38 3d ff ff ff 07 13 04 11 05 20 16 14 3e b6 5a 20 a8 fc db 2d 61 38 27 ff ff ff 08 18 58 0c 11 05 20 db 8e 0a 99 5a 20 73 be cb 32 61 38 10 ff ff ff 08 06 fe 04 0d 20 9d 6c 0b a0 38 01 ff ff ff 06 18 5b 8d 62 00 00 01 0b 11 05 20 df 10 fe 24 5a 20 cd 6f d2 94 61 38 e5 fe ff ff } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_FormBook_NL_MTB_3{
	meta:
		description = "Trojan:BAT/FormBook.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {1a 5e 45 04 00 00 00 32 00 00 00 02 00 00 00 dc ff ff ff 1d 00 00 00 2b 30 02 02 7b 41 00 00 04 28 a3 00 00 06 06 20 6f 2c ad 05 5a 20 33 be 5e 53 61 2b c4 } //01 00 
		$a_01_1 = {20 b5 88 b2 41 61 25 0d 1a 5e 45 04 00 00 00 37 00 00 00 02 00 00 00 1f 00 00 00 dc ff ff ff 2b 35 07 08 30 08 20 16 b9 65 13 25 2b 06 20 fc 1f 01 55 25 26 09 20 ff 4e 0a 0b 5a 61 2b c2 06 16 07 28 6a 04 00 06 0a 09 20 46 7d 3d 58 5a 20 99 34 c6 7b 61 2b aa } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_FormBook_NL_MTB_4{
	meta:
		description = "Trojan:BAT/FormBook.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {4f 00 35 00 39 00 53 00 43 00 45 00 48 00 47 00 38 00 47 00 34 00 38 00 52 00 52 00 35 00 41 00 4a 00 51 00 49 00 34 00 35 00 34 00 } //01 00  O59SCEHG8G48RR5AJQI454
		$a_01_1 = {4d 44 35 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //01 00  MD5CryptoServiceProvider
		$a_01_2 = {54 72 69 70 6c 65 44 45 53 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //01 00  TripleDESCryptoServiceProvider
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_4 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00  TransformFinalBlock
		$a_01_5 = {47 65 74 42 79 74 65 73 } //00 00  GetBytes
	condition:
		any of ($a_*)
 
}