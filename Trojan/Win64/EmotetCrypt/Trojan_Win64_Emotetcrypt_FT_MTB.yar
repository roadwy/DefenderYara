
rule Trojan_Win64_Emotetcrypt_FT_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.FT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {4b 35 57 38 6a 6e 58 32 74 48 34 62 67 4e 34 63 49 63 71 76 4c 35 34 44 6a 6b 32 76 71 79 36 4c 73 62 4f 68 34 54 35 66 55 } //1 K5W8jnX2tH4bgN4cIcqvL54Djk2vqy6LsbOh4T5fU
		$a_81_1 = {4c 6f 6f 6b 42 65 61 75 74 69 66 75 6c 6c 79 } //1 LookBeautifully
		$a_81_2 = {4c 65 61 76 65 43 6c 6f 73 65 } //1 LeaveClose
		$a_81_3 = {62 64 74 61 7a 72 63 77 74 6a 63 68 66 74 72 67 6e } //1 bdtazrcwtjchftrgn
		$a_81_4 = {63 68 6d 69 78 72 67 69 78 66 71 6d 66 6a 6a 64 69 } //1 chmixrgixfqmfjjdi
		$a_81_5 = {66 74 61 68 6a 66 65 74 6d 72 78 6b 71 70 6e 65 7a } //1 ftahjfetmrxkqpnez
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}