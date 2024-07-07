
rule Ransom_Win64_GhostLocker_YAA_MTB{
	meta:
		description = "Ransom:Win64/GhostLocker.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 } //1 Go build ID: "
		$a_01_1 = {41 4c 4c 20 59 4f 55 52 20 46 49 4c 45 53 20 41 52 45 } //1 ALL YOUR FILES ARE
		$a_01_2 = {53 54 4f 4c 45 4e 20 41 4e 44 20 45 4e 43 52 59 50 54 45 44 21 } //1 STOLEN AND ENCRYPTED!
		$a_01_3 = {45 4e 43 52 59 50 54 49 4f 4e 20 49 44 3a } //1 ENCRYPTION ID:
		$a_01_4 = {61 73 73 69 73 74 20 79 6f 75 20 69 6e 20 64 65 63 72 79 70 74 69 6e 67 } //1 assist you in decrypting
		$a_01_5 = {68 74 74 70 3a 2f 2f 39 34 2e 31 30 33 2e 39 31 2e 32 34 36 2f } //1 http://94.103.91.246/
		$a_03_6 = {49 83 c2 10 4c 8d 5b 01 4c 89 d3 4d 89 c1 49 89 f0 4c 89 de 48 39 f1 7e 90 01 01 49 89 da 4c 8b 5b 08 4d 85 db 75 90 01 01 48 89 f3 4c 89 c6 4d 89 c8 eb 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_03_6  & 1)*1) >=7
 
}