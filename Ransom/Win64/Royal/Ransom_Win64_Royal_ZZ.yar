
rule Ransom_Win64_Royal_ZZ{
	meta:
		description = "Ransom:Win64/Royal.ZZ,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 03 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_03_1 = {48 89 00 48 89 40 08 48 89 43 08 ff 15 ?? ?? ?? ?? 45 33 c0 8d 56 01 8d 4e 02 ff 15 ?? ?? ?? ?? 48 8b f8 48 83 f8 ff 74 6c 48 89 74 24 40 48 8d 4c 24 60 48 89 74 24 38 48 8d 83 18 60 00 00 48 89 4c 24 30 44 8d 4e 10 c7 44 24 28 08 00 00 00 4c 8d 44 24 50 48 8b cf 48 89 44 24 20 ba 06 00 00 c8 c7 44 24 50 b9 07 a2 25 c7 44 24 54 f3 dd 60 46 c7 44 24 58 8e e9 76 e5 c7 44 24 5c 8c 74 06 3e ff 15 ?? ?? ?? ?? 85 } //10
		$a_01_2 = {c7 41 0c 02 00 00 00 0f 57 c0 48 c7 01 ff ff ff ff 48 8d 52 30 89 71 08 48 8d 49 30 0f 11 42 d0 0f 11 42 e0 48 83 e8 01 75 d6 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*10+(#a_01_2  & 1)*10) >=21
 
}