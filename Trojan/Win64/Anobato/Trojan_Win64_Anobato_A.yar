
rule Trojan_Win64_Anobato_A{
	meta:
		description = "Trojan:Win64/Anobato.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 83 ec 08 48 83 ec 20 eb 0a 6e 74 64 6c 6c 2e 64 6c 6c 00 48 8d 0d ef ff ff ff ff 15 90 01 04 48 83 c4 20 90 00 } //1
		$a_01_1 = {48 05 04 d0 07 00 48 81 be b0 01 00 00 0c 0c 0c 0c 75 09 } //1
		$a_01_2 = {72 65 67 73 76 72 6d 6f 62 73 79 6e 72 75 6e 64 6c 6c 72 75 6e 6f 6e 63 } //2 regsvrmobsynrundllrunonc
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2) >=4
 
}
rule Trojan_Win64_Anobato_A_2{
	meta:
		description = "Trojan:Win64/Anobato.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {31 08 81 38 55 48 89 e5 74 0c 48 83 fb 00 75 06 31 08 ff c1 eb ea } //1
		$a_03_1 = {48 83 ec 20 48 c7 c1 00 00 00 00 48 c7 c2 00 80 02 00 49 c7 c0 00 30 00 00 49 c7 c1 40 00 00 00 ff 15 90 01 04 48 83 c4 20 48 83 f8 00 75 02 eb ce 90 00 } //1
		$a_01_2 = {81 fb 04 04 00 00 73 09 48 83 c0 04 83 c3 04 eb } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_Win64_Anobato_A_3{
	meta:
		description = "Trojan:Win64/Anobato.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {48 83 ec 20 eb 0d 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 48 8d 0d ec ff ff ff ff 15 90 01 04 48 83 c4 20 90 90 90 00 } //1
		$a_01_1 = {48 83 ec 20 48 c7 c1 00 00 00 00 48 c7 c2 00 14 00 00 49 c7 c0 00 30 00 00 49 c7 c1 04 00 00 00 ff d0 } //1
		$a_01_2 = {eb 06 38 35 2e 39 33 00 } //1
		$a_01_3 = {eb 06 2e 30 2e 32 32 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule Trojan_Win64_Anobato_A_4{
	meta:
		description = "Trojan:Win64/Anobato.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_03_0 = {41 8b 0f 67 8b 49 04 41 8b 17 01 da 83 c2 0c 67 31 0a 41 3b 87 90 01 02 00 00 73 08 83 c0 04 83 c3 04 eb e4 90 00 } //1
		$a_01_1 = {49 8b 1f 8b 43 08 83 f8 00 74 07 80 7c 03 ff c3 74 02 eb 26 } //1
		$a_01_2 = {00 64 48 83 ec 20 48 c7 c1 00 00 00 00 48 c7 c2 00 40 01 00 49 c7 c0 00 30 00 00 49 c7 c1 40 00 00 00 41 ff } //1
		$a_01_3 = {eb 0f 31 39 33 2e 32 38 2e 31 37 39 2e 31 30 35 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}