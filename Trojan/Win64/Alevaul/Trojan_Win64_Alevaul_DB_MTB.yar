
rule Trojan_Win64_Alevaul_DB_MTB{
	meta:
		description = "Trojan:Win64/Alevaul.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {0f b6 f8 42 0f b6 54 17 08 8d 04 16 0f b6 f0 42 8a 44 16 08 42 88 44 17 08 42 88 54 16 08 42 0f b6 4c 17 08 03 ca 81 e1 ff 00 00 80 } //10
		$a_01_1 = {41 0f b6 c9 44 88 4c 04 38 8b c2 0f b6 44 04 38 03 c1 25 ff 00 00 80 } //10
		$a_01_2 = {0f b6 d8 41 0f b6 14 18 8d 04 17 0f b6 f8 0f b6 04 39 41 88 04 18 88 14 39 41 0f b6 04 18 03 c2 25 ff 00 00 80 } //10
		$a_01_3 = {48 63 c1 42 8a 4c 10 08 42 32 0c 1b 41 88 0b 49 ff c3 49 ff c9 } //5
		$a_01_4 = {48 63 c8 49 ff c3 0f b6 44 0c 38 41 32 43 ff 48 ff c3 88 43 ff c7 84 24 50 01 00 00 98 b4 01 00 } //5
		$a_01_5 = {48 63 c8 49 ff c1 0f b6 44 0c 18 43 32 44 0b ff 41 88 41 ff 49 ff ca } //5
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5+(#a_01_5  & 1)*5) >=15
 
}