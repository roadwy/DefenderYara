
rule Trojan_Win64_CryptInject_BSA_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {f2 0f 11 44 24 08 48 83 ec 68 0f b6 05 69 4c 53 01 0f be c0 f2 0f 2a c0 0f b6 05 5a 4c 53 01 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}
rule Trojan_Win64_CryptInject_BSA_MTB_2{
	meta:
		description = "Trojan:Win64/CryptInject.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {79 6f 75 20 63 6c 69 63 6b 65 64 20 61 20 61 64 64 72 65 73 73 } //10 you clicked a address
		$a_01_1 = {79 6f 75 20 63 6c 69 63 6b 65 64 20 61 20 62 75 73 20 73 74 61 74 69 6f 6e 21 } //10 you clicked a bus station!
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}
rule Trojan_Win64_CryptInject_BSA_MTB_3{
	meta:
		description = "Trojan:Win64/CryptInject.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 02 00 00 "
		
	strings :
		$a_03_0 = {eb 21 48 8b 45 e8 48 3b 45 e0 75 09 c7 45 f0 ?? ?? ?? ?? eb 45 b9 e8 03 00 00 48 8b 05 be 40 29 00 ff d0 48 8b 05 ?? ?? ?? ?? 48 89 45 c8 } //10
		$a_03_1 = {f0 48 0f b1 0a 48 89 45 e8 48 83 7d e8 ?? 75 a8 48 8b 05 ?? ?? ?? ?? 8b 00 83 f8 01 } //2
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*2) >=12
 
}
rule Trojan_Win64_CryptInject_BSA_MTB_4{
	meta:
		description = "Trojan:Win64/CryptInject.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 2b e0 48 8b 05 ?? ?? ?? ?? 48 33 c4 48 89 84 24 e0 20 00 00 41 b9 0f 0f 05 00 4c 8b 84 24 ?? ?? ?? ?? 48 8d 94 24 ?? ?? ?? ?? 48 8d 8c 24 } //11
		$a_01_1 = {48 8d 84 08 94 0a 00 00 89 44 24 5c c7 44 24 20 00 00 00 00 48 8d 94 24 68 02 00 00 48 8d 4c 24 30 } //10
	condition:
		((#a_03_0  & 1)*11+(#a_01_1  & 1)*10) >=21
 
}
rule Trojan_Win64_CryptInject_BSA_MTB_5{
	meta:
		description = "Trojan:Win64/CryptInject.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 06 00 00 "
		
	strings :
		$a_01_0 = {6d 61 74 72 69 78 31 2e 74 78 74 } //4 matrix1.txt
		$a_01_1 = {72 65 73 75 6c 74 5f 6d 61 74 72 69 78 2e 74 78 74 } //4 result_matrix.txt
		$a_01_2 = {41 b9 0a 00 00 00 42 f6 44 f0 38 48 74 79 42 8a 44 f0 3a 41 3a c1 74 6f 85 ed } //2
		$a_01_3 = {4b 8b 04 c3 42 8a 4c f0 3b 41 3a c9 74 45 85 ed 74 41 41 88 0f 41 8d 79 f8 4b } //2
		$a_01_4 = {3c 41 3a c9 74 19 85 ed 74 15 41 88 0f 41 8d 79 f9 4b 8b 04 c3 4c 03 fa ff cd } //2
		$a_01_5 = {46 88 4c f0 3c 41 8b cd e8 92 76 00 00 85 c0 } //2
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=16
 
}