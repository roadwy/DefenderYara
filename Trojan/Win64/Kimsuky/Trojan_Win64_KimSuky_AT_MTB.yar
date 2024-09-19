
rule Trojan_Win64_KimSuky_AT_MTB{
	meta:
		description = "Trojan:Win64/KimSuky.AT!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {54 66 75 44 76 73 73 66 6f 75 45 6a 73 66 64 75 70 73 7a 42 00 00 00 00 47 6a 6d 66 55 6a 6e 66 55 70 4d 70 64 62 6d 47 6a 6d 66 55 6a 6e 66 00 47 6a 6d 66 55 6a 6e 66 55 70 54 7a 74 75 66 6e } //1
		$a_01_1 = {b8 01 00 00 00 48 85 db 48 0f 44 d8 4c 8b c7 33 d2 4c 8b cb } //1
		$a_01_2 = {ff 41 80 ff 49 74 44 41 80 ff 68 74 35 41 80 ff 6c 74 14 41 80 ff 77 0f 85 f5 fb ff ff 41 0f ba ee 0b e9 eb fb ff ff 80 3f 6c 75 0d 48 ff c7 41 0f ba ee 0c e9 d9 fb ff ff 41 83 ce 10 e9 d0 fb } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}