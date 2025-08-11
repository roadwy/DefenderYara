
rule Ransom_Win64_NightSpire_YAF_MTB{
	meta:
		description = "Ransom:Win64/NightSpire.YAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {65 6e 63 72 79 70 74 65 64 20 62 79 20 4e 69 67 68 74 53 70 69 72 65 20 52 61 6e 73 6f 6d 77 61 72 65 } //1 encrypted by NightSpire Ransomware
		$a_01_1 = {64 65 63 72 79 70 74 69 6f 6e 20 6b 65 79 } //1 decryption key
		$a_01_2 = {75 73 65 20 74 68 69 72 64 2d 70 61 72 74 79 20 73 6f 66 74 77 61 72 65 } //1 use third-party software
		$a_01_3 = {64 61 74 61 62 61 73 65 73 20 61 72 65 20 73 74 6f 6c 65 6e } //1 databases are stolen
		$a_01_4 = {47 6f 20 62 75 69 6c 64 20 49 44 3a } //1 Go build ID:
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}